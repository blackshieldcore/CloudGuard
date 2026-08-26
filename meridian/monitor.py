"""
meridian/monitor.py
~~~~~~~~~~~~~~~~~~~
CloudTrail anomaly detection and IAM honeypot deployer.

CloudTrailMonitor:
  Pulls the last N hours of CloudTrail events and cross-references them
  against the IAM permission graph.  Flags any API call made by a principal
  whose known policy graph shows LOW/MEDIUM privilege but the action is a
  HIGH-risk edge.

HoneypotDeployer:
  Creates a decoy IAM role (meridian-canary-admin) that looks attractive
  to an attacker probing for privilege escalation.  Monitors CloudTrail for
  AssumeRole events on the honeypot ARN and fires a webhook alert.

⚠️  HoneypotDeployer REQUIRES:
  - iam:CreateRole, iam:PutRolePolicy, iam:AttachRolePolicy
  - s3:CreateBucket, s3:PutObject
  - Pass --confirm-deploy to prevent accidental creation
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

try:
    import boto3
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    import urllib.request
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

from meridian.rules import PRIVESC_ACTIONS, HIGH_RISK_SERVICES


# ──────────────────────────────────────────────
# CloudTrail Anomaly Monitor
# ──────────────────────────────────────────────

class CloudTrailMonitor:
    """
    Pulls CloudTrail events and flags anomalous actions.

    An anomaly is: a principal performed a HIGH-risk action (one that appears
    in PRIVESC_ACTIONS or touches HIGH_RISK_SERVICES) but their policy graph
    shows them as a LOW/MEDIUM-risk principal.
    """

    def __init__(self, session: Optional[Any] = None, region: str = "us-east-1"):
        if not HAS_BOTO3:
            raise ImportError("boto3 required for --monitor mode.  pip install boto3")
        self.session = session or boto3.Session(region_name=region)
        self.cloudtrail = self.session.client("cloudtrail", region_name=region)

    def pull_events(self, hours: int = 24, max_results: int = 1000) -> List[dict]:
        """
        Pull CloudTrail management events from the last `hours` hours.
        Returns a list of event dicts.
        """
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        events = []
        kwargs = {
            "StartTime": start_time,
            "MaxResults": min(max_results, 50),  # API max per page
        }
        print(f"  [MONITOR] Pulling CloudTrail events (last {hours}h)...", file=sys.stderr)

        try:
            while len(events) < max_results:
                response = self.cloudtrail.lookup_events(**kwargs)
                events.extend(response.get("Events", []))
                next_token = response.get("NextToken")
                if not next_token or len(events) >= max_results:
                    break
                kwargs["NextToken"] = next_token
        except ClientError as e:
            print(f"  [ERROR] CloudTrail lookup failed: {e}", file=sys.stderr)

        print(f"  [MONITOR] Fetched {len(events)} events", file=sys.stderr)
        return events

    def analyze_anomalies(
        self, events: List[dict], high_risk_principals: Optional[List[str]] = None
    ) -> List[dict]:
        """
        Flag events where:
          - The action is in PRIVESC_ACTIONS or touches a HIGH_RISK_SERVICE
          - The calling principal is NOT in the high_risk_principals list
            (i.e., they should not be performing this action)

        If high_risk_principals is None, flags ALL high-risk actions.
        """
        anomalies = []
        for event in events:
            event_name   = event.get("EventName", "")
            event_source = event.get("EventSource", "").replace(".amazonaws.com", "")
            username     = event.get("Username", "UNKNOWN")
            event_time   = event.get("EventTime")
            resources    = event.get("Resources", [])

            # Construct the full action name (e.g., "iam:CreateUser")
            full_action = f"{event_source}:{event_name}"

            is_privesc    = full_action in PRIVESC_ACTIONS
            is_high_risk_svc = event_source.lower() in HIGH_RISK_SERVICES

            if not (is_privesc or is_high_risk_svc):
                continue

            # If we have a known-high-risk list, skip those principals
            if high_risk_principals and username in high_risk_principals:
                continue

            anomalies.append({
                "event_name":    event_name,
                "event_source":  event_source,
                "full_action":   full_action,
                "username":      username,
                "event_time":    str(event_time),
                "is_privesc":    is_privesc,
                "is_high_risk":  is_high_risk_svc,
                "resources":     [r.get("ARN", r.get("ResourceName", "")) for r in resources],
                "cloudtrail_id": event.get("EventId", ""),
                "severity":      "HIGH" if is_privesc else "MEDIUM",
            })

        return anomalies

    def print_anomalies(self, anomalies: List[dict], output_format: str = "text"):
        """Print anomaly report to stdout."""
        if output_format == "json":
            print(json.dumps(anomalies, indent=2, default=str))
            return

        if not anomalies:
            print("  [MONITOR] No anomalous CloudTrail events detected.")
            return

        print(f"\n{'='*60}")
        print(f"  CLOUDTRAIL ANOMALY REPORT  ({len(anomalies)} findings)")
        print(f"{'='*60}")
        for a in anomalies:
            sev = a["severity"]
            print(f"\n[{sev}] {a['full_action']}")
            print(f"  Principal : {a['username']}")
            print(f"  Time      : {a['event_time']}")
            print(f"  Resources : {a['resources']}")
            print(f"  Privesc?  : {a['is_privesc']}")
            print(f"  Event ID  : {a['cloudtrail_id']}")
        print(f"\n{'='*60}\n")


# ──────────────────────────────────────────────
# Honeypot Deployer
# ──────────────────────────────────────────────

HONEYPOT_ROLE_NAME   = "meridian-canary-admin"
HONEYPOT_POLICY_NAME = "meridian-canary-policy"
HONEYPOT_BUCKET_PREFIX = "meridian-canary-"

DECOY_SECRET_CONTENT = json.dumps({
    "description": "AWS master credentials — DO NOT SHARE",
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "region": "us-east-1",
    "note": "These are fake credentials placed by Meridian honeypot.",
}, indent=2)


class HoneypotDeployer:
    """
    Deploys a decoy IAM role + S3 bucket to detect attackers probing for
    privilege escalation paths.

    The honeypot looks like an admin role but only has s3:GetObject on a
    specific canary bucket containing fake credentials.
    """

    def __init__(
        self,
        session: Optional[Any] = None,
        region: str = "us-east-1",
        org_id: Optional[str] = None,
    ):
        if not HAS_BOTO3:
            raise ImportError("boto3 required for honeypot deployment.  pip install boto3")
        self.session   = session or boto3.Session(region_name=region)
        self.region    = region
        self.org_id    = org_id
        self.iam       = self.session.client("iam")
        self.s3        = self.session.client("s3", region_name=region)
        self.sts       = self.session.client("sts")
        self._role_arn: Optional[str] = None
        self._bucket:   Optional[str] = None

    def _get_account_id(self) -> str:
        return self.sts.get_caller_identity()["Account"]

    def deploy(self, bucket_name: Optional[str] = None) -> str:
        """
        Create the honeypot role and canary S3 bucket.
        Returns the honeypot role ARN.
        """
        account_id = self._get_account_id()
        self._bucket = bucket_name or f"{HONEYPOT_BUCKET_PREFIX}{account_id}"

        print(f"  [HONEYPOT] Deploying honeypot role: {HONEYPOT_ROLE_NAME}", file=sys.stderr)
        print(f"  [HONEYPOT] Canary bucket: {self._bucket}", file=sys.stderr)

        # 1. Create the canary S3 bucket
        self._create_canary_bucket(self._bucket)

        # 2. Upload decoy secrets file
        self._upload_decoy(self._bucket)

        # 3. Build trust policy (broad — to attract attackers)
        trust_policy = self._build_trust_policy(account_id)

        # 4. Create the decoy IAM role
        role_arn = self._create_honeypot_role(trust_policy)

        # 5. Attach a policy (limited — only s3:GetObject on canary bucket)
        self._attach_canary_policy(self._bucket)

        self._role_arn = role_arn
        print(f"  [HONEYPOT] Deployed.  Role ARN: {role_arn}", file=sys.stderr)
        print(f"  [HONEYPOT] Run --watch-honeypot {role_arn} to start monitoring.", file=sys.stderr)
        return role_arn

    def _build_trust_policy(self, account_id: str) -> dict:
        """Build a broad trust policy to make the role look appealing to attackers."""
        principals: Any = {"AWS": f"arn:aws:iam::{account_id}:root"}
        conditions = {}

        if self.org_id:
            conditions = {
                "StringEquals": {"aws:PrincipalOrgID": self.org_id}
            }

        stmt: dict = {
            "Effect": "Allow",
            "Principal": principals,
            "Action": "sts:AssumeRole",
        }
        if conditions:
            stmt["Condition"] = conditions

        return {"Version": "2012-10-17", "Statement": [stmt]}

    def _create_canary_bucket(self, bucket_name: str):
        try:
            if self.region == "us-east-1":
                self.s3.create_bucket(Bucket=bucket_name)
            else:
                self.s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": self.region},
                )
            # Block all public access
            self.s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            print(f"  [HONEYPOT] Created bucket {bucket_name}", file=sys.stderr)
        except ClientError as e:
            if e.response["Error"]["Code"] == "BucketAlreadyOwnedByYou":
                print(f"  [HONEYPOT] Bucket {bucket_name} already exists", file=sys.stderr)
            else:
                raise

    def _upload_decoy(self, bucket_name: str):
        """Upload a fake credentials file to the canary bucket."""
        self.s3.put_object(
            Bucket=bucket_name,
            Key="credentials.json",
            Body=DECOY_SECRET_CONTENT.encode("utf-8"),
            ContentType="application/json",
        )
        print(f"  [HONEYPOT] Uploaded decoy credentials.json to {bucket_name}", file=sys.stderr)

    def _create_honeypot_role(self, trust_policy: dict) -> str:
        """Create the decoy IAM role with an enticing name."""
        try:
            response = self.iam.create_role(
                RoleName=HONEYPOT_ROLE_NAME,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=(
                    "Meridian canary role — DO NOT USE. "
                    "Monitors for unauthorized AssumeRole attempts."
                ),
                Tags=[
                    {"Key": "meridian:honeypot", "Value": "true"},
                    {"Key": "meridian:created", "Value": datetime.now().isoformat()},
                ],
            )
            return response["Role"]["Arn"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityAlreadyExists":
                print("  [HONEYPOT] Role already exists", file=sys.stderr)
                return self.iam.get_role(RoleName=HONEYPOT_ROLE_NAME)["Role"]["Arn"]
            raise

    def _attach_canary_policy(self, bucket_name: str):
        """Attach a minimal policy — only s3:GetObject on the canary bucket."""
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                }
            ],
        }
        self.iam.put_role_policy(
            RoleName=HONEYPOT_ROLE_NAME,
            PolicyName=HONEYPOT_POLICY_NAME,
            PolicyDocument=json.dumps(policy_doc),
        )
        print(f"  [HONEYPOT] Attached canary policy (s3:GetObject only)", file=sys.stderr)

    def destroy(self):
        """Remove the honeypot role and canary bucket."""
        print("  [HONEYPOT] Destroying honeypot resources...", file=sys.stderr)
        try:
            self.iam.delete_role_policy(
                RoleName=HONEYPOT_ROLE_NAME,
                PolicyName=HONEYPOT_POLICY_NAME,
            )
        except ClientError:
            pass
        try:
            self.iam.delete_role(RoleName=HONEYPOT_ROLE_NAME)
            print(f"  [HONEYPOT] Deleted role {HONEYPOT_ROLE_NAME}", file=sys.stderr)
        except ClientError as e:
            print(f"  [HONEYPOT] Could not delete role: {e}", file=sys.stderr)

        if self._bucket:
            try:
                # Empty bucket first
                objs = self.s3.list_objects_v2(Bucket=self._bucket).get("Contents", [])
                for obj in objs:
                    self.s3.delete_object(Bucket=self._bucket, Key=obj["Key"])
                self.s3.delete_bucket(Bucket=self._bucket)
                print(f"  [HONEYPOT] Deleted bucket {self._bucket}", file=sys.stderr)
            except ClientError as e:
                print(f"  [HONEYPOT] Could not delete bucket: {e}", file=sys.stderr)


# ──────────────────────────────────────────────
# Honeypot Watcher
# ──────────────────────────────────────────────

def watch_honeypot(
    role_arn: str,
    webhook_url: Optional[str] = None,
    poll_interval: int = 60,
    session: Optional[Any] = None,
    region: str = "us-east-1",
):
    """
    Continuously poll CloudTrail for AssumeRole events on the honeypot role ARN.
    Sends a webhook alert when the honeypot is touched.

    Runs indefinitely until Ctrl-C.
    """
    if not HAS_BOTO3:
        raise ImportError("boto3 required for --watch-honeypot.  pip install boto3")

    session   = session or boto3.Session(region_name=region)
    cloudtrail = session.client("cloudtrail", region_name=region)

    print(f"  [WATCH] Monitoring honeypot: {role_arn}")
    print(f"  [WATCH] Poll interval: {poll_interval}s  |  Webhook: {webhook_url or 'none'}")
    print("  Press Ctrl-C to stop.\n")

    seen_event_ids = set()

    while True:
        start_time = datetime.now(timezone.utc) - timedelta(seconds=poll_interval * 2)
        try:
            response = cloudtrail.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": "AssumeRole"}
                ],
                StartTime=start_time,
                MaxResults=50,
            )
            for event in response.get("Events", []):
                event_id = event.get("EventId", "")
                if event_id in seen_event_ids:
                    continue

                # Check if the assumed role ARN matches our honeypot
                ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                req = ct_event.get("requestParameters", {})
                assumed_arn = req.get("roleArn", "")

                if role_arn in assumed_arn:
                    seen_event_ids.add(event_id)
                    alert = {
                        "alert":       "HONEYPOT_TRIGGERED",
                        "honeypot_arn": role_arn,
                        "caller":      event.get("Username", "UNKNOWN"),
                        "source_ip":   ct_event.get("sourceIPAddress", "UNKNOWN"),
                        "event_time":  str(event.get("EventTime")),
                        "event_id":    event_id,
                    }
                    _fire_alert(alert, webhook_url)

        except ClientError as e:
            print(f"  [WATCH] CloudTrail error: {e}", file=sys.stderr)

        time.sleep(poll_interval)


def _fire_alert(alert: dict, webhook_url: Optional[str]):
    """Print alert and optionally POST to a Slack/Discord webhook."""
    msg = (
        f"\n🚨 HONEYPOT TRIGGERED!\n"
        f"  ARN    : {alert['honeypot_arn']}\n"
        f"  Caller : {alert['caller']}\n"
        f"  Source : {alert['source_ip']}\n"
        f"  Time   : {alert['event_time']}\n"
        f"  ID     : {alert['event_id']}\n"
    )
    print(msg)

    if not webhook_url:
        return

    # Slack/Discord compatible payload
    payload = json.dumps({
        "text": f"*Meridian Honeypot Alert* 🚨\n```{json.dumps(alert, indent=2)}```"
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"  [WATCH] Alert sent to webhook.")
    except Exception as e:
        print(f"  [WATCH] Webhook delivery failed: {e}", file=sys.stderr)
