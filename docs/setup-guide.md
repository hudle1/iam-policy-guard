# Setup guide: from zero to a secure AWS sandbox

This walks through everything needed before the code runs: a dedicated AWS account, locked-down root, a single sign-on admin login, local tools, the GitHub repo, and the OIDC role. It assumes no existing AWS setup.

Written November 2026. The AWS console changes often; if a screen differs from what's described, the goal of each step stays the same.

**Time:** ~1.5 hours total. **Cost:** cents per month (see [Cost](../README.md#cost)).

**Placeholders used below**

| Placeholder | Meaning |
| --- | --- |
| `<you>@gmail.com` | Your email. Gmail `+` aliases (`<you>+aws-root@gmail.com`) need no setup and deliver to your normal inbox |
| `<ACCOUNT_ID>` | Your 12-digit AWS account ID (top-right menu in the console) |
| `<PORTAL_URL>` | Your IAM Identity Center access portal URL, e.g. `https://d-xxxxxxxxxx.awsapps.com/start` |
| `<github-user>` | Your GitHub username |

---

## Phase 1: Create a standard AWS account (~20 min)

Use a **new, dedicated account** for this project. Don't use a work account.

**Have ready:** a card, your phone, a password manager, and an authenticator app.

1. Open a **private browser window** (avoids old sessions and autofill from other AWS accounts).
2. Go to `https://portal.aws.amazon.com/billing/signup` (or `aws.amazon.com` → **Create account**).
3. **Make sure you're on the standard signup path.** The correct page is titled **Sign up for AWS** and asks for a **root user email address** and **AWS account name**.
   - ⚠️ **Pitfall:** AWS also offers a newer, simplified signup ("What do you want to create?", sign-in with Google/GitHub/Apple, *projects*). Accounts created that way have no root user, use AWS-managed policies you can't change, and **deny IAM Access Analyzer**, so this project can't run on them. If you see that flow, look for an **advanced** / standard option instead.
4. **Root user email:** `<you>+aws-root@gmail.com`. **Account name:** e.g. `sandbox`. Verify the emailed code.
5. **Root password:** 20+ random characters from your password manager. Save it *before* continuing.
6. **Plan:** choose **Paid plan**.
   - The Free plan closes the account after 6 months. Paid still includes any sign-up credits and only bills beyond them; this project costs cents.
7. Contact info: a phone number you'll keep (it's your MFA recovery path), address matching your card.
8. Card, then SMS identity check, then **Basic support – Free**, then **Complete sign up**.
9. Sign in at `https://console.aws.amazon.com` → **Sign in using root user email**.
10. **Verify:** the top bar shows a **Region selector** and no "Projects" menu. Open `https://console.aws.amazon.com/access-analyzer/home?region=us-east-1`: it should load with **no "Access denied"** panel. Don't click **Create analyzer** (analyzers bill monthly and this project doesn't use them).

## Phase 2: Lock down root + budget alarm (~15 min)

### Root MFA: register two devices
1. Console → top-right account menu → **Security credentials** (`https://console.aws.amazon.com/iam/home#/security_credentials`).
2. **Assign MFA device** → name `root-phone-app` → **Authenticator app** → scan QR → enter two *consecutive* codes → **Add MFA**.
3. Turn on cloud backup in your authenticator app.
4. **Sign out and back in with MFA.**
   - ⚠️ **Pitfall:** adding a second device fails with *"ensure that you are authenticated with an MFA device"* until your session itself used MFA.
5. **Assign MFA device** again → name `root-passkey` → **Passkey or security key** → complete the browser prompt.
   - If the prompt hangs (common in embedded browsers), use Chrome/Edge, or add a second authenticator app instead.

**Why two:** losing your only MFA device on an account whose root password you've also lost means a slow AWS Support recovery.

### $10 budget alarm
1. `https://console.aws.amazon.com/costmanagement/home#/budgets` → **Create budget**.
2. **Use a template (simplified)** → **Monthly cost budget**.
3. Name `monthly-10-usd`, amount `10`, your email → **Create budget**.

You'll be emailed at 85% and 100% of actual spend and 100% of forecast. If you create the budget here, leave `budget_email` unset in `infra/terraform.tfvars` so Terraform doesn't create a duplicate.

## Phase 3: Everyday admin login with IAM Identity Center (~20 min)

Root is now break-glass only. Daily work uses IAM Identity Center (single sign-on): short-lived sessions, MFA, no long-lived keys.

### Enable it
1. Open `https://console.aws.amazon.com/singlesignon/home?region=us-east-1` (the URL sets the Region; Identity Center's Region is hard to change later).
   - The Region selector may look locked on global pages like IAM; that's normal.
2. **Enable** → choose **Single-Region instance**. Leave **Additional Region** empty.
   - Multi-Region creates a customer managed KMS key (extra cost) for failover a sandbox doesn't need.
3. This creates an **organization instance** and an **AWS Organization** (your account becomes the management account).
4. **Verify** on the Dashboard: **Primary Region `us-east-1`**, **Identity source: Identity Center directory**.
5. Copy the **IPv4-only** access portal URL (`<PORTAL_URL>`) into your password manager.
6. Optional: **Instance name → Edit** → e.g. `sandbox-sso`.

### Require MFA
**Settings → Authentication → Multi-factor authentication → Configure:**
- Prompt users for MFA: **Every time they sign in (always-on)**
- MFA types: both checked
- No registered device: **Require them to register an MFA device at sign in**
- **Save changes**

### Create your user
**Users → Add user:** username of your choice, **Send an email with password setup instructions**, email `<you>+aws-admin@gmail.com` (a different alias from root), first/last name → **Next** → skip groups → **Add user**.

### Admin permission set
⚠️ **Pitfall:** do this in **IAM Identity Center**, not **IAM**. The IAM console also has a "Multi-account access" menu, but permission sets live only in Identity Center.

**Multi-account permissions → Permission sets → Create permission set → Predefined → AdministratorAccess → Next →** session duration **4 hours** → **Next → Create**.

### Assign it
**Multi-account permissions → AWS accounts →** check your account → **Assign users or groups → Users →** your user → **Next → AdministratorAccess → Next → Submit**.

### Activate and test
1. Accept the **"Invitation to join AWS IAM Identity Center"** email, set a password, register MFA.
2. In the portal: your name (top right) → **MFA devices → Register device** → add a passkey as a backup.
3. Portal → expand your account → click **AdministratorAccess**. The console opens.
4. **Verify:** top right shows **AdministratorAccess/<username>**.
5. Sign out of root.

**How sign-in works now**

| As | Where |
| --- | --- |
| Your SSO user (daily) | `<PORTAL_URL>` (no account ID field) |
| Root (emergencies) | `https://console.aws.amazon.com` → **Sign in using root user email** |

⚠️ **Pitfall:** the console's **IAM user sign in** form (Account ID + username) is only for IAM users. This account has none, so your SSO user will always be rejected there.

**Portal vs console:** signing in to the portal proves who you are. Clicking **AdministratorAccess** starts a separate, temporary console session with that role (up to the session duration you set).

### Optional: billing pages for your SSO user
Billing and account-settings pages show "You don't have permission" for every non-root identity until root enables it: sign in as root → `https://console.aws.amazon.com/billing/home#/account` → **IAM user and role access to Billing information → Edit → Activate IAM Access → Update**.

## Phase 4: Install the AWS CLI and Terraform

_To be added._

## Phase 5: Create the GitHub repo

_To be added._ Includes enabling secret scanning and push protection **before** the first push.

## Phase 6: Deploy the OIDC role and connect GitHub

_To be added._ Summary: `cd infra && cp terraform.tfvars.example terraform.tfvars`, fill it in, `terraform init && terraform apply`, then set the repo Actions secret `AWS_ROLE_ARN`.

## Phase 7: Anthropic API key

_To be added._ Stored as the repo Actions secret `ANTHROPIC_API_KEY`.

---

## Teardown
1. `cd infra && terraform destroy`
2. Optional: close the account (root → **Account** → **Close account**). Closed accounts can be reopened for 90 days.
