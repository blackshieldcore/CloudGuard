"""
meridian/live.py
~~~~~~~~~~~~~~~~
Live AWS IAM scanner.  Pulls all IAM policies from a live account using boto3
and feeds them into Meridian's dict-based loader.

Authentication uses the standard AWS SDK credential chain — no credentials are
ever hardcoded:
  1. Environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
  2. ~/.aws/credentials profile
  3. EC2/ECS/Lambda instance metadata role
  4. AWS SSO / IAM Identity Center

Multi-account support: provide a list of account IDs to scan via
--accounts.  Meridian will call sts:AssumeRole on the specified role name
(default: OrganizationAccountAccessRole) in each account.

Usage:
    scanner = AWSLiveScanner(profile="my-profile")
    policies = scanner.pull_all_policies()
    m = Meridian()
    for name, doc in policies.items():
        m.load_dict(name, doc)
    findings = m.analyze()
"""

from __future__ import annotations

import json
import sys
from typing import Dict, List, Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


class AWSLiveScanner:
    """
    Pulls all IAM policies, user policies, role policies (including trust
    policies), and group policies from one or more AWS accounts.
    """

    def __init__(
        self,
        profile: Optional[str] = None,
        region: str = "us-east-1",
        role_to_assume: str = "OrganizationAccountAccessRole",
    ):
        if not HAS_BOTO3:
            raise ImportError(
                "boto3 is required for --live mode.\n"
                "Install it with:  pip install boto3"
            )
        self.profile = profile
        self.region = region
        self.role_to_assume = role_to_assume
        self._base_session = boto3.Session(
            profile_name=profile, region_name=region
        )

    # ── Session management ────────────────────

    def _get_session(self, account_id: Optional[str] = None) -> "boto3.Session":
        """Return a session for the given account (cross-account via STS if needed)."""
        if account_id is None:
            return self._base_session

        sts = self._base_session.client("sts")
        role_arn = f"arn:aws:iam::{account_id}:role/{self.role_to_assume}"
        print(f"  [LIVE] Assuming role {role_arn} ...", file=sys.stderr)
        try:
            creds = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="CloudGuardLiveScan",
            )["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region,
            )
        except ClientError as e:
            print(f"  [ERROR] Cannot assume role in {account_id}: {e}", file=sys.stderr)
            return None

    def _iam(self, session: "boto3.Session"):
        return session.client("iam")

    # ── Org account discovery ─────────────────

    def discover_org_accounts(self) -> List[str]:
        """
        List all active account IDs in the AWS Organization.
        Requires organizations:ListAccounts permission.
        """
        org = self._base_session.client("organizations")
        accounts = []
        paginator = org.get_paginator("list_accounts")
        try:
            for page in paginator.paginate():
                for acct in page["Accounts"]:
                    if acct["Status"] == "ACTIVE":
                        accounts.append(acct["Id"])
            print(f"  [LIVE] Discovered {len(accounts)} org accounts", file=sys.stderr)
        except ClientError as e:
            print(f"  [WARN] Org discovery failed: {e}", file=sys.stderr)
        return accounts

    # ── Policy pulling ────────────────────────

    def pull_all_policies(
        self, account_ids: Optional[List[str]] = None
    ) -> Dict[str, dict]:
        """
        Pull all IAM policies from the given accounts (or the calling account).
        Returns {label: policy_doc_dict} ready for CloudGuard.load_dict().
        """
        result: Dict[str, dict] = {}

        if not account_ids:
            account_ids = [None]  # None = current account

        for account_id in account_ids:
            label_prefix = f"aws://{account_id}" if account_id else "aws://current"
            session = self._get_session(account_id)
            if session is None:
                continue
            print(f"  [LIVE] Scanning {label_prefix} ...", file=sys.stderr)
            try:
                result.update(self._pull_account(session, label_prefix))
            except NoCredentialsError:
                print(
                    "  [ERROR] No AWS credentials found.  Configure via environment "
                    "variables, ~/.aws/credentials, or an IAM role.",
                    file=sys.stderr,
                )
                break
            except ClientError as e:
                print(f"  [ERROR] AWS API error for {label_prefix}: {e}", file=sys.stderr)

        return result

    def _pull_account(self, session: "boto3.Session", prefix: str) -> Dict[str, dict]:
        """Pull all policy docs for one account session."""
        iam = self._iam(session)
        docs: Dict[str, dict] = {}

        # 1. Customer-managed policies (Scope=Local)
        docs.update(self._pull_managed_policies(iam, prefix))

        # 2. Inline + attached policies on users
        docs.update(self._pull_user_policies(iam, prefix))

        # 3. Inline + attached policies on roles + trust policies
        docs.update(self._pull_role_policies(iam, prefix))

        # 4. Inline + attached policies on groups
        docs.update(self._pull_group_policies(iam, prefix))

        print(
            f"  [LIVE] {prefix}: loaded {len(docs)} policy documents",
            file=sys.stderr,
        )
        return docs

    def _pull_managed_policies(self, iam, prefix: str) -> Dict[str, dict]:
        """List all customer-managed policies and fetch their default versions."""
        docs = {}
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                name = policy["PolicyName"]
                arn  = policy["Arn"]
                version_id = policy["DefaultVersionId"]
                try:
                    version = iam.get_policy_version(
                        PolicyArn=arn, VersionId=version_id
                    )
                    doc = version["PolicyVersion"]["Document"]
                    # AWS returns URL-encoded JSON for managed policies
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    docs[f"{prefix}/managed/{name}"] = doc
                except ClientError as e:
                    print(f"  [WARN] Cannot fetch {name}: {e}", file=sys.stderr)
        return docs

    def _pull_user_policies(self, iam, prefix: str) -> Dict[str, dict]:
        docs = {}
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]

                # Inline policies
                inl_pager = iam.get_paginator("list_user_policies")
                for inl_page in inl_pager.paginate(UserName=uname):
                    for pname in inl_page["PolicyNames"]:
                        try:
                            doc = iam.get_user_policy(UserName=uname, PolicyName=pname)[
                                "PolicyDocument"
                            ]
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            docs[f"{prefix}/users/{uname}/inline/{pname}"] = doc
                        except ClientError:
                            pass

                # Attached managed policies
                att_pager = iam.get_paginator("list_attached_user_policies")
                for att_page in att_pager.paginate(UserName=uname):
                    for policy in att_page["AttachedPolicies"]:
                        arn = policy["PolicyArn"]
                        pname = policy["PolicyName"]
                        try:
                            meta = iam.get_policy(PolicyArn=arn)["Policy"]
                            ver = iam.get_policy_version(
                                PolicyArn=arn,
                                VersionId=meta["DefaultVersionId"],
                            )
                            doc = ver["PolicyVersion"]["Document"]
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            docs[f"{prefix}/users/{uname}/attached/{pname}"] = doc
                        except ClientError:
                            pass
        return docs

    def _pull_role_policies(self, iam, prefix: str) -> Dict[str, dict]:
        docs = {}
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                rname = role["RoleName"]

                # Trust policy (AssumeRolePolicyDocument)
                trust_doc = role.get("AssumeRolePolicyDocument")
                if trust_doc:
                    if isinstance(trust_doc, str):
                        trust_doc = json.loads(trust_doc)
                    docs[f"{prefix}/roles/{rname}/trust"] = trust_doc

                # Inline policies
                inl_pager = iam.get_paginator("list_role_policies")
                for inl_page in inl_pager.paginate(RoleName=rname):
                    for pname in inl_page["PolicyNames"]:
                        try:
                            doc = iam.get_role_policy(RoleName=rname, PolicyName=pname)[
                                "PolicyDocument"
                            ]
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            docs[f"{prefix}/roles/{rname}/inline/{pname}"] = doc
                        except ClientError:
                            pass

                # Attached managed policies
                att_pager = iam.get_paginator("list_attached_role_policies")
                for att_page in att_pager.paginate(RoleName=rname):
                    for policy in att_page["AttachedPolicies"]:
                        arn = policy["PolicyArn"]
                        pname = policy["PolicyName"]
                        try:
                            meta = iam.get_policy(PolicyArn=arn)["Policy"]
                            ver = iam.get_policy_version(
                                PolicyArn=arn,
                                VersionId=meta["DefaultVersionId"],
                            )
                            doc = ver["PolicyVersion"]["Document"]
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            docs[f"{prefix}/roles/{rname}/attached/{pname}"] = doc
                        except ClientError:
                            pass
        return docs

    def _pull_group_policies(self, iam, prefix: str) -> Dict[str, dict]:
        docs = {}
        paginator = iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for group in page["Groups"]:
                gname = group["GroupName"]

                # Inline policies
                inl_pager = iam.get_paginator("list_group_policies")
                for inl_page in inl_pager.paginate(GroupName=gname):
                    for pname in inl_page["PolicyNames"]:
                        try:
                            doc = iam.get_group_policy(GroupName=gname, PolicyName=pname)[
                                "PolicyDocument"
                            ]
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            docs[f"{prefix}/groups/{gname}/inline/{pname}"] = doc
                        except ClientError:
                            pass

                # Attached managed policies
                att_pager = iam.get_paginator("list_attached_group_policies")
                for att_page in att_pager.paginate(GroupName=gname):
                    for policy in att_page["AttachedPolicies"]:
                        arn = policy["PolicyArn"]
                        pname = policy["PolicyName"]
                        try:
                            meta = iam.get_policy(PolicyArn=arn)["Policy"]
                            ver = iam.get_policy_version(
                                PolicyArn=arn,
                                VersionId=meta["DefaultVersionId"],
                            )
                            doc = ver["PolicyVersion"]["Document"]
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            docs[f"{prefix}/groups/{gname}/attached/{pname}"] = doc
                        except ClientError:
                            pass
        return docs
