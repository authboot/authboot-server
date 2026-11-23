-- Run before deploying the authorization changes.
-- Existing memberships have no ownership evidence: do not infer owner from ID
-- or grant all existing members management access.
ALTER TABLE tb_organization_membership
  ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'member';

-- REQUIRED deployment step: have the organization administrator verify and
-- explicitly provision at least one owner for each existing organization:
-- UPDATE tb_organization_membership SET role = 'owner'
-- WHERE organization_id = <verified_org_id> AND account_id = <verified_owner_id>
--   AND status = 2;
-- Membership status follows membership.proto: 1=pending, 2=active, 3=disabled,
-- 4=removed. It is distinct from the user/organization enabled status (1).
-- Existing trusted operators may be assigned 'admin' by the owner using
-- PUT /api/v1/admin/organizations/:organization_id/members/:membership_id/role
-- {"role":"admin"}. Other memberships remain 'member' (no management access).
-- New organizations create their owner transactionally; accepted invitations
-- default to member. No global superadmin or cross-organization bypass exists.
