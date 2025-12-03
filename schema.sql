

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


CREATE SCHEMA IF NOT EXISTS "kit";


ALTER SCHEMA "kit" OWNER TO "postgres";


COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE EXTENSION IF NOT EXISTS "pg_graphql" WITH SCHEMA "graphql";






CREATE EXTENSION IF NOT EXISTS "pg_stat_statements" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault";






CREATE EXTENSION IF NOT EXISTS "unaccent" WITH SCHEMA "kit";






CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA "extensions";






CREATE TYPE "public"."app_permissions" AS ENUM (
    'roles.manage',
    'billing.manage',
    'settings.manage',
    'members.manage',
    'invites.manage'
);


ALTER TYPE "public"."app_permissions" OWNER TO "postgres";


CREATE TYPE "public"."invitation" AS (
	"email" "text",
	"role" character varying(50)
);


ALTER TYPE "public"."invitation" OWNER TO "postgres";


CREATE TYPE "public"."line_status" AS ENUM (
    'following',
    'unfollowed'
);


ALTER TYPE "public"."line_status" OWNER TO "postgres";


CREATE TYPE "public"."payment_status" AS ENUM (
    'pending',
    'succeeded',
    'failed'
);


ALTER TYPE "public"."payment_status" OWNER TO "postgres";


CREATE TYPE "public"."subscription_item_type" AS ENUM (
    'flat',
    'per_seat',
    'metered'
);


ALTER TYPE "public"."subscription_item_type" OWNER TO "postgres";


CREATE TYPE "public"."subscription_role" AS ENUM (
    'Premium',
    'Pro'
);


ALTER TYPE "public"."subscription_role" OWNER TO "postgres";


CREATE TYPE "public"."subscription_status" AS ENUM (
    'active',
    'trialing',
    'past_due',
    'canceled',
    'unpaid',
    'incomplete',
    'incomplete_expired',
    'paused'
);


ALTER TYPE "public"."subscription_status" OWNER TO "postgres";


CREATE TYPE "public"."user_roles" AS ENUM (
    'admin',
    'user',
    'guest',
    'owner'
);


ALTER TYPE "public"."user_roles" OWNER TO "postgres";


CREATE TYPE "public"."workspace_role" AS ENUM (
    'member',
    'admin'
);


ALTER TYPE "public"."workspace_role" OWNER TO "postgres";


CREATE TYPE "public"."workspace_status" AS ENUM (
    'pending',
    'cancel',
    'reject',
    'answer'
);


ALTER TYPE "public"."workspace_status" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "kit"."add_current_user_to_new_account"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO ''
    AS $$
begin
    if new.primary_owner_user_id = auth.uid() then
        insert into public.accounts_memberships(
            account_id,
            user_id,
            account_role)
        values(
            new.id,
            auth.uid(),
            public.get_upper_system_role());
    end if;
    return NEW;
end;
$$;


ALTER FUNCTION "kit"."add_current_user_to_new_account"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "kit"."check_team_account"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    if(
        select
            is_personal_account
        from
            public.accounts
        where
            id = new.account_id) then
        raise exception 'Account must be an team account';

    end if;

    return NEW;
end;
$$;


ALTER FUNCTION "kit"."check_team_account"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "kit"."get_storage_filename_as_uuid"("name" "text") RETURNS "uuid"
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    return replace(storage.filename(name), concat('.',
	storage.extension(name)), '')::uuid;
end;
$$;


ALTER FUNCTION "kit"."get_storage_filename_as_uuid"("name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "kit"."handle_update_user_email"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO ''
    AS $$
begin
    update
        public.accounts
    set
        email = new.email
    where
        primary_owner_user_id = new.id
        and is_personal_account = true;
    return new;
end;
$$;


ALTER FUNCTION "kit"."handle_update_user_email"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "kit"."prevent_account_owner_membership_delete"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    if exists(
      select
          1
      from
          public.accounts
      where
          id = old.account_id
          and primary_owner_user_id = old.user_id)
    then
      raise exception 'The primary account owner cannot be removed from the account membership list';
    end if;
    return old;
end;
$$;


ALTER FUNCTION "kit"."prevent_account_owner_membership_delete"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "kit"."prevent_memberships_update"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    if new.account_role <> old.account_role then
        return new;
    end if;
    raise exception 'Only the account_role can be updated';
end;
$$;


ALTER FUNCTION "kit"."prevent_memberships_update"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "kit"."protect_account_fields"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    if current_user in('authenticated', 'anon') then
      if new.id <> old.id or new.is_personal_account <>
        old.is_personal_account or new.primary_owner_user_id <>
        old.primary_owner_user_id or new.email <> old.email 
      then
        raise exception 'You do not have permission to update this field';
      end if;
    end if;
    return NEW;
end
$$;


ALTER FUNCTION "kit"."protect_account_fields"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "kit"."set_slug_from_account_name"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO ''
    AS $$
declare
    sql_string varchar;
    tmp_slug varchar;
    increment integer;
    tmp_row record;
    tmp_row_count integer;
begin
    tmp_row_count = 1;

    increment = 0;

    while tmp_row_count > 0 loop
        if increment > 0 then
            tmp_slug = kit.slugify(new.name || ' ' || increment::varchar);

        else
            tmp_slug = kit.slugify(new.name);

        end if;

	sql_string = format('select count(1) cnt from public.accounts where slug = ''' || tmp_slug ||
	    '''; ');

        for tmp_row in execute (sql_string)
            loop
                raise notice 'tmp_row %', tmp_row;

                tmp_row_count = tmp_row.cnt;

            end loop;

        increment = increment +1;

    end loop;

    new.slug := tmp_slug;

    return NEW;

end
$$;


ALTER FUNCTION "kit"."set_slug_from_account_name"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "kit"."setup_new_user"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO ''
    AS $$
declare
    user_name text;
    picture_url text;
begin
    if new.raw_user_meta_data ->> 'name' is not null then
        user_name := new.raw_user_meta_data ->> 'name';

    end if;

    if user_name is null and new.email is not null then
        user_name := split_part(new.email, '@', 1);

    end if;

    if user_name is null then
        user_name := '';

    end if;

    if new.raw_user_meta_data ->> 'avatar_url' is not null then
        picture_url := new.raw_user_meta_data ->> 'avatar_url';
    else
        picture_url := null;
    end if;

    insert into public.accounts(
        id,
        primary_owner_user_id,
        name,
        is_personal_account,
        picture_url,
        email)
    values (
        new.id,
        new.id,
        user_name,
        true,
        picture_url,
        new.email);

    return new;

end;

$$;


ALTER FUNCTION "kit"."setup_new_user"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "kit"."slugify"("value" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE STRICT
    SET "search_path" TO ''
    AS $_$
    -- removes accents (diacritic signs) from a given string --
    with "unaccented" as(
        select
            kit.unaccent("value") as "value"
),
"lowercase" as(
    select
        lower("value") as "value"
    from
        "unaccented"
),
"removed_quotes" as(
    select
	regexp_replace("value", '[''"]+', '',
	    'gi') as "value"
    from
        "lowercase"
),
"hyphenated" as(
    select
	regexp_replace("value", '[^a-z0-9\\-_]+', '-',
	    'gi') as "value"
    from
        "removed_quotes"
),
"trimmed" as(
            select
          regexp_replace(regexp_replace("value", '\-+$',
              ''), '^\-', '') as "value" from "hyphenated"
        )
        select
            "value"
        from
            "trimmed";
$_$;


ALTER FUNCTION "kit"."slugify"("value" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."accept_invitation"("token" "text", "user_id" "uuid") RETURNS "uuid"
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
declare
    target_account_id uuid;
    target_role varchar(50);
begin
    select
        account_id,
        role
    into
        target_account_id,
        target_role
    from
        public.invitations
    where
        invite_token = token
        and expires_at > now();

    if not found then
        raise exception 'Invalid or expired invitation token';
    end if;

    insert into public.accounts_memberships(
        user_id,
        account_id,
        account_role)
    values (
        accept_invitation.user_id,
        target_account_id,
        target_role);

    delete from public.invitations
    where invite_token = token;

    return target_account_id;
end;
$$;


ALTER FUNCTION "public"."accept_invitation"("token" "text", "user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_action_account_member"("target_team_account_id" "uuid", "target_user_id" "uuid") RETURNS boolean
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
declare
    permission_granted boolean;
    target_user_hierarchy_level int;
    current_user_hierarchy_level int;
    is_account_owner boolean;
    target_user_role varchar(50);
begin
    if target_user_id = auth.uid() then
      raise exception 'You cannot update your own account membership with this function';
    end if;

    -- an account owner can action any member of the account
    if public.is_account_owner(target_team_account_id) then
      return true;
    end if;

    -- check the target user is the primary owner of the account
    select
        exists (
            select
                1
            from
                public.accounts
            where
                id = target_team_account_id
                and primary_owner_user_id = target_user_id) into is_account_owner;

    if is_account_owner then
        raise exception 'The primary account owner cannot be actioned';
    end if;

    -- validate the auth user has the required permission on the account
    -- to manage members of the account
    select
      public.has_permission(auth.uid(), target_team_account_id,
          'members.manage'::public.app_permissions) into
          permission_granted;

    -- if the user does not have the required permission, raise an exception
    if not permission_granted then
      raise exception 'You do not have permission to action a member from this account';
    end if;

    -- get the role of the target user
    select
        am.account_role,
        r.hierarchy_level
    from
        public.accounts_memberships as am
    join
        public.roles as r on am.account_role = r.name
    where
        am.account_id = target_team_account_id
        and am.user_id = target_user_id
    into target_user_role, target_user_hierarchy_level;

    -- get the hierarchy level of the current user
    select
        r.hierarchy_level into current_user_hierarchy_level
    from
        public.roles as r
    join
        public.accounts_memberships as am on r.name = am.account_role
    where
        am.account_id = target_team_account_id
        and am.user_id = auth.uid();

    if target_user_role is null then
      raise exception 'The target user does not have a role on the account';
    end if;

    if current_user_hierarchy_level is null then
      raise exception 'The current user does not have a role on the account';
    end if;

    -- check the current user has a higher role than the target user
    if current_user_hierarchy_level >= target_user_hierarchy_level then
      raise exception 'You do not have permission to action a member from this account';
    end if;

    return true;
end;
$$;


ALTER FUNCTION "public"."can_action_account_member"("target_team_account_id" "uuid", "target_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cancel_workspace"("c_workspace_owner_id" "uuid", "c_user_owner_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$
declare
begin
perform('transaction.read_only', 'off', true);

delete from public.workspace_invite where public.workspace_invite.workspace_owner_id = c_workspace_owner_id and public.workspace_invite.user_owner_id = c_user_owner_id;
delete from public.workspace_member where public.workspace_member.workspace_owner_id = c_workspace_owner_id and public.workspace_member.user_id_owner_id = c_user_owner_id;

exception
when others then
raise;
end;
$$;


ALTER FUNCTION "public"."cancel_workspace"("c_workspace_owner_id" "uuid", "c_user_owner_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_onboarding_and_workspace"("p_user_id" "uuid", "p_description" json, "p_user_type" character varying, "p_workspace_name" character varying) RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$
begin
  perform set_config('transaction.read_only', 'off', true);

  begin
    insert into onboarding (user_id, description, user_type)
    values (p_user_id, p_description, p_user_type);

    insert into workspace (name, user_id)
    values (p_workspace_name, p_user_id);

  exception when others then
    raise; -- แจ้ง error กลับออกไป
  end;
end;
$$;


ALTER FUNCTION "public"."create_onboarding_and_workspace"("p_user_id" "uuid", "p_description" json, "p_user_type" character varying, "p_workspace_name" character varying) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_account_invitations"("account_slug" "text") RETURNS TABLE("id" integer, "email" character varying, "account_id" "uuid", "invited_by" "uuid", "role" character varying, "created_at" timestamp with time zone, "updated_at" timestamp with time zone, "expires_at" timestamp with time zone, "inviter_name" character varying, "inviter_email" character varying)
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    return query
    select
        invitation.id,
        invitation.email,
        invitation.account_id,
        invitation.invited_by,
        invitation.role,
        invitation.created_at,
        invitation.updated_at,
        invitation.expires_at,
        account.name,
        account.email
    from
        public.invitations as invitation
        join public.accounts as account on invitation.account_id = account.id
    where
        account.slug = account_slug;

end;

$$;


ALTER FUNCTION "public"."get_account_invitations"("account_slug" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_account_members"("account_slug" "text") RETURNS TABLE("id" "uuid", "user_id" "uuid", "account_id" "uuid", "role" character varying, "role_hierarchy_level" integer, "primary_owner_user_id" "uuid", "name" character varying, "email" character varying, "picture_url" character varying, "created_at" timestamp with time zone, "updated_at" timestamp with time zone)
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    return QUERY
    select
        acc.id,
        am.user_id,
        am.account_id,
        am.account_role,
        r.hierarchy_level,
        a.primary_owner_user_id,
        acc.name,
        acc.email,
        acc.picture_url,
        am.created_at,
        am.updated_at
    from
        public.accounts_memberships am
        join public.accounts a on a.id = am.account_id
        join public.accounts acc on acc.id = am.user_id
        join public.roles r on r.name = am.account_role
    where
        a.slug = account_slug;

end;

$$;


ALTER FUNCTION "public"."get_account_members"("account_slug" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_config"() RETURNS json
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
declare
    result record;
begin
    select
        *
    from
        public.config
    limit 1 into result;

    return row_to_json(result);
end;
$$;


ALTER FUNCTION "public"."get_config"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_upper_system_role"() RETURNS character varying
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
declare
    role varchar(50);
begin
    select name from public.roles
      where hierarchy_level = 1 into role;

    return role;
end;
$$;


ALTER FUNCTION "public"."get_upper_system_role"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."has_active_subscription"("target_account_id" "uuid") RETURNS boolean
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    return exists (
        select
            1
        from
            public.subscriptions
        where
            account_id = target_account_id
            and active = true);
end;
$$;


ALTER FUNCTION "public"."has_active_subscription"("target_account_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."has_more_elevated_role"("target_user_id" "uuid", "target_account_id" "uuid", "role_name" character varying) RETURNS boolean
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
declare
    declare is_primary_owner boolean;
    user_role_hierarchy_level int;
    target_role_hierarchy_level int;
begin
    -- Check if the user is the primary owner of the account
    select
        exists (
            select
                1
            from
                public.accounts
            where
                id = target_account_id
                and primary_owner_user_id = target_user_id) into is_primary_owner;

    -- If the user is the primary owner, they have the highest role and can
    --   perform any action
    if is_primary_owner then
        return true;
    end if;

    -- Get the hierarchy level of the user's role within the account
    select
        hierarchy_level into user_role_hierarchy_level
    from
        public.roles
    where
        name =(
            select
                account_role
            from
                public.accounts_memberships
            where
                account_id = target_account_id
                and target_user_id = user_id);

    if user_role_hierarchy_level is null then
        return false;
    end if;

    -- Get the hierarchy level of the target role
    select
        hierarchy_level into target_role_hierarchy_level
    from
        public.roles
    where
        name = role_name;

    -- If the target role does not exist, the user cannot perform the action
    if target_role_hierarchy_level is null then
        return false;
    end if;

    -- If the user's role is higher than the target role, they can perform
    --   the action
    return user_role_hierarchy_level < target_role_hierarchy_level;
end;
$$;


ALTER FUNCTION "public"."has_more_elevated_role"("target_user_id" "uuid", "target_account_id" "uuid", "role_name" character varying) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."has_permission"("user_id" "uuid", "account_id" "uuid", "permission_name" "public"."app_permissions") RETURNS boolean
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    return exists(
        select
            1
        from
            public.accounts_memberships
        join public.role_permissions on
            accounts_memberships.account_role = role_permissions.role
        where
            accounts_memberships.user_id = has_permission.user_id
            and accounts_memberships.account_id = has_permission.account_id
            and role_permissions.permission = has_permission.permission_name);
end;
$$;


ALTER FUNCTION "public"."has_permission"("user_id" "uuid", "account_id" "uuid", "permission_name" "public"."app_permissions") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."has_role_on_account"("account_id" "uuid", "account_role" character varying DEFAULT NULL::character varying) RETURNS boolean
    LANGUAGE "sql" SECURITY DEFINER
    SET "search_path" TO ''
    AS $$
    select
        exists(
            select
                1
            from
                public.accounts_memberships membership
            where
                membership.user_id = (select auth.uid())
                and membership.account_id = has_role_on_account.account_id
                and((membership.account_role = has_role_on_account.account_role
                    or has_role_on_account.account_role is null)));
$$;


ALTER FUNCTION "public"."has_role_on_account"("account_id" "uuid", "account_role" character varying) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."has_same_role_hierarchy_level"("target_user_id" "uuid", "target_account_id" "uuid", "role_name" character varying) RETURNS boolean
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
declare
    is_primary_owner boolean;
    user_role_hierarchy_level int;
    target_role_hierarchy_level int;
begin
    -- Check if the user is the primary owner of the account
    select
        exists (
            select
                1
            from
                public.accounts
            where
                id = target_account_id
                and primary_owner_user_id = target_user_id) into is_primary_owner;

    -- If the user is the primary owner, they have the highest role and can perform any action
    if is_primary_owner then
        return true;
    end if;

    -- Get the hierarchy level of the user's role within the account
    select
        hierarchy_level into user_role_hierarchy_level
    from
        public.roles
    where
        name =(
            select
                account_role
            from
                public.accounts_memberships
            where
                account_id = target_account_id
                and target_user_id = user_id);

    -- If the user does not have a role in the account, they cannot perform the action
    if user_role_hierarchy_level is null then
        return false;
    end if;

    -- Get the hierarchy level of the target role
    select
        hierarchy_level into target_role_hierarchy_level
    from
        public.roles
    where
        name = role_name;

    -- If the target role does not exist, the user cannot perform the action
    if target_role_hierarchy_level is null then
        return false;
    end if;

    -- check the user's role hierarchy level is the same as the target role
    return user_role_hierarchy_level = target_role_hierarchy_level;
end;
$$;


ALTER FUNCTION "public"."has_same_role_hierarchy_level"("target_user_id" "uuid", "target_account_id" "uuid", "role_name" character varying) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."insert_subscription"("s_sub_id" character varying, "s_inv_id" character varying, "s_cus_id" character varying, "s_id" character varying, "s_status" character varying, "s_user_id" "uuid", "s_created_at" timestamp without time zone, "s_updated_at" timestamp without time zone, "s_expires_at" timestamp without time zone, "l_item_id" character varying, "l_item_price_id" character varying, "l_item_product_id" character varying, "l_item_productname" character varying, "l_item_created_at" timestamp without time zone, "l_item_updated_at" timestamp without time zone) RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$declare
  i_line_id uuid;
begin

  insert into public.subscription_lineitems 
  (
   line_items_id,
   price_id,
   product_id,
   productname,
   created_at,
   updated_at
  ) values (
    l_item_id,
    l_item_price_id,
    l_item_product_id,
    l_item_productname,
    l_item_created_at,
    l_item_updated_at
  ) returning id into i_line_id;

  insert into public.subscription (
    id,
    subscription_id,
    subscription_customer_id,
    subscription_invoice_id,
    subscription_status,
    user_owner_subscription_id,
    created_at,
    expires_at,
    updated_at,
    itemlines_id
  ) values (
    s_id,
    s_sub_id,
    s_cus_id,
    s_inv_id,
    s_status,
    s_user_id,
    s_created_at,
    s_expires_at,
    s_updated_at,
    i_line_id
  )
  on conflict (subscription_id) do update
    set
      subscription_customer_id = excluded.subscription_customer_id,
      subscription_invoice_id = excluded.subscription_invoice_id,
      subscription_status = excluded.subscription_status,
      user_owner_subscription_id = excluded.user_owner_subscription_id,
      created_at = excluded.created_at,
      expires_at = excluded.expires_at,
      updated_at = excluded.updated_at,
      itemlines_id = excluded.itemlines_id;

exception
when others then
  raise;
end;$$;


ALTER FUNCTION "public"."insert_subscription"("s_sub_id" character varying, "s_inv_id" character varying, "s_cus_id" character varying, "s_id" character varying, "s_status" character varying, "s_user_id" "uuid", "s_created_at" timestamp without time zone, "s_updated_at" timestamp without time zone, "s_expires_at" timestamp without time zone, "l_item_id" character varying, "l_item_price_id" character varying, "l_item_product_id" character varying, "l_item_productname" character varying, "l_item_created_at" timestamp without time zone, "l_item_updated_at" timestamp without time zone) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_account_owner"("account_id" "uuid") RETURNS boolean
    LANGUAGE "sql"
    SET "search_path" TO ''
    AS $$
    select
        exists(
            select
                1
            from
                public.accounts
            where
                id = is_account_owner.account_id
                and primary_owner_user_id = auth.uid());
$$;


ALTER FUNCTION "public"."is_account_owner"("account_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_account_team_member"("target_account_id" "uuid") RETURNS boolean
    LANGUAGE "sql"
    SET "search_path" TO ''
    AS $$
    select exists(
        select 1
        from public.accounts_memberships as membership
        where public.is_team_member (membership.account_id, target_account_id)
    );
$$;


ALTER FUNCTION "public"."is_account_team_member"("target_account_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_set"("field_name" "text") RETURNS boolean
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
declare
    result boolean;
begin
    execute format('select %I from public.config limit 1', field_name) into result;
    return result;
end;
$$;


ALTER FUNCTION "public"."is_set"("field_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_team_member"("account_id" "uuid", "user_id" "uuid") RETURNS boolean
    LANGUAGE "sql" SECURITY DEFINER
    SET "search_path" TO ''
    AS $$
    select
        exists(
            select
                1
            from
                public.accounts_memberships membership
            where
                public.has_role_on_account(account_id)
                and membership.user_id = is_team_member.user_id
                and membership.account_id = is_team_member.account_id);
$$;


ALTER FUNCTION "public"."is_team_member"("account_id" "uuid", "user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."team_account_workspace"("account_slug" "text") RETURNS TABLE("id" "uuid", "name" character varying, "picture_url" character varying, "slug" "text", "email" character varying, "role" character varying, "role_hierarchy_level" integer, "primary_owner_user_id" "uuid", "subscription_status" "public"."subscription_status", "permissions" "public"."app_permissions"[])
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    return QUERY
    select
        accounts.id,
        accounts.name,
        accounts.picture_url,
        accounts.slug,
        accounts.email,
        accounts_memberships.account_role,
        roles.hierarchy_level,
        accounts.primary_owner_user_id,
        subscriptions.status,
        array_agg(role_permissions.permission)
    from
        public.accounts
        join public.accounts_memberships on accounts.id = accounts_memberships.account_id
        left join public.subscriptions on accounts.id = subscriptions.account_id
        join public.roles on accounts_memberships.account_role = roles.name
        left join public.role_permissions on accounts_memberships.account_role = role_permissions.role
    where
        accounts.slug = account_slug
        and public.accounts_memberships.user_id = (select auth.uid())
    group by
        accounts.id,
        accounts_memberships.account_role,
        subscriptions.status,
        roles.hierarchy_level;
end;
$$;


ALTER FUNCTION "public"."team_account_workspace"("account_slug" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."transfer_team_account_ownership"("target_account_id" "uuid", "new_owner_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    if current_user not in('service_role') then
        raise exception 'You do not have permission to transfer account ownership';
    end if;

    -- verify the user is already a member of the account
    if not exists(
        select
            1
        from
            public.accounts_memberships
        where
            target_account_id = account_id
            and user_id = new_owner_id) then
        raise exception 'The new owner must be a member of the account';
    end if;

    -- update the primary owner of the account
    update
        public.accounts
    set
        primary_owner_user_id = new_owner_id
    where
        id = target_account_id
        and is_personal_account = false;

    -- update membership assigning it the hierarchy role
    update
        public.accounts_memberships
    set
        account_role =(
            public.get_upper_system_role())
    where
        target_account_id = account_id
        and user_id = new_owner_id
        and account_role <>(
            public.get_upper_system_role());
end;
$$;


ALTER FUNCTION "public"."transfer_team_account_ownership"("target_account_id" "uuid", "new_owner_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."trigger_set_timestamps"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    if TG_OP = 'INSERT' then
        new.created_at = now();

        new.updated_at = now();
    else
        new.updated_at = now();

        new.created_at = old.created_at;
    end if;
    return NEW;
end
$$;


ALTER FUNCTION "public"."trigger_set_timestamps"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."trigger_set_user_tracking"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO ''
    AS $$
begin
    if TG_OP = 'INSERT' then
        new.created_by = auth.uid();
        new.updated_by = auth.uid();
    else
        new.updated_by = auth.uid();
        new.created_by = old.created_by;
    end if;
    return NEW;
end
$$;


ALTER FUNCTION "public"."trigger_set_user_tracking"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."workspace_approved"("w_user_owner_id" "uuid", "w_workspace_owner_id" "uuid", "w_invited_by" "uuid", "w_workspace_status" "public"."workspace_status", "w_role" "public"."workspace_role", "w_joined" timestamp without time zone) RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$declare 
begin
perform set_config('transaction.read_only', 'off', true);

insert into public.workspace_member 
(workspace_owner_id, user_id_owner_id, role, invited_by, joined_at) values 
(w_workspace_owner_id, w_user_owner_id, w_role, w_invited_by, w_joined);

update workspace_invite set workspace_status = w_workspace_status
where public.workspace_invite.user_owner_id = w_user_owner_id and public.workspace_invite.workspace_owner_id = w_workspace_owner_id and public.workspace_invite.invited_by = w_invited_by;

exception
when others then
raise;
end;$$;


ALTER FUNCTION "public"."workspace_approved"("w_user_owner_id" "uuid", "w_workspace_owner_id" "uuid", "w_invited_by" "uuid", "w_workspace_status" "public"."workspace_status", "w_role" "public"."workspace_role", "w_joined" timestamp without time zone) OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."account" (
    "id" "uuid" DEFAULT "auth"."uid"() NOT NULL,
    "username" character varying DEFAULT '255'::character varying,
    "email" character varying DEFAULT '255'::character varying NOT NULL,
    "role" "public"."user_roles" DEFAULT 'user'::"public"."user_roles" NOT NULL,
    "created_at" timestamp without time zone DEFAULT "now"(),
    "updated_at" timestamp without time zone DEFAULT "now"(),
    "avatar_url" character varying
);


ALTER TABLE "public"."account" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."onboarding" (
    "id" bigint NOT NULL,
    "user_id" "uuid",
    "description" json NOT NULL,
    "workspace" character varying DEFAULT 'workspace'::character varying,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "user_type" character varying
);


ALTER TABLE "public"."onboarding" OWNER TO "postgres";


ALTER TABLE "public"."onboarding" ALTER COLUMN "id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."onboarding_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."subscription" (
    "id" character varying NOT NULL,
    "subscription_customer_id" character varying,
    "subscription_id" character varying NOT NULL,
    "subscription_invoice_id" character varying NOT NULL,
    "subscription_status" character varying,
    "user_owner_subscription_id" "uuid" DEFAULT "gen_random_uuid"(),
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "expires_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "itemlines_id" "uuid"
);


ALTER TABLE "public"."subscription" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."subscription_lineitems" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "line_items_id" character varying NOT NULL,
    "price_id" character varying NOT NULL,
    "product_id" character varying NOT NULL,
    "productname" character varying,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."subscription_lineitems" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."subscription_user_role" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_owner_id" "uuid" NOT NULL,
    "user_role" "public"."subscription_role" DEFAULT 'Pro'::"public"."subscription_role" NOT NULL,
    "interval" character varying DEFAULT 'Month'::character varying NOT NULL,
    "cus_id" character varying DEFAULT 'cus_TDM1sDrS0T6Tnu'::character varying NOT NULL
);


ALTER TABLE "public"."subscription_user_role" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."workspace" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" character varying NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "workspace_icon" character varying DEFAULT 'LayoutDashboard'::character varying
);


ALTER TABLE "public"."workspace" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."workspace_invite" (
    "workspace_owner_id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "invited_by" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_owner_id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "workspace_status" "public"."workspace_status" DEFAULT 'pending'::"public"."workspace_status",
    "updated_at" timestamp without time zone DEFAULT "now"(),
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "expired_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL
);


ALTER TABLE "public"."workspace_invite" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."workspace_member" (
    "workspace_owner_id" "uuid" NOT NULL,
    "user_id_owner_id" "uuid",
    "invited_by" "uuid",
    "joined_at" timestamp without time zone DEFAULT "now"(),
    "role" "public"."workspace_role" DEFAULT 'member'::"public"."workspace_role",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL
);


ALTER TABLE "public"."workspace_member" OWNER TO "postgres";


ALTER TABLE ONLY "public"."account"
    ADD CONSTRAINT "account_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."onboarding"
    ADD CONSTRAINT "onboarding_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."subscription_lineitems"
    ADD CONSTRAINT "subscription_lineitems_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."subscription"
    ADD CONSTRAINT "subscription_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."subscription"
    ADD CONSTRAINT "subscription_subscription_id_key" UNIQUE ("subscription_id");



ALTER TABLE ONLY "public"."subscription"
    ADD CONSTRAINT "subscription_subscription_invoice_id_key" UNIQUE ("subscription_invoice_id");



ALTER TABLE ONLY "public"."subscription_user_role"
    ADD CONSTRAINT "subscription_user_role_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."workspace_invite"
    ADD CONSTRAINT "workspace_invite_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."workspace_member"
    ADD CONSTRAINT "workspace_member_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."workspace"
    ADD CONSTRAINT "workspace_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."onboarding"
    ADD CONSTRAINT "onborad_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."account"("id");



ALTER TABLE ONLY "public"."subscription"
    ADD CONSTRAINT "subscription_itemlines_id_fkey" FOREIGN KEY ("itemlines_id") REFERENCES "public"."subscription_lineitems"("id");



ALTER TABLE ONLY "public"."subscription"
    ADD CONSTRAINT "subscription_user_owner_subscription_id_fkey" FOREIGN KEY ("user_owner_subscription_id") REFERENCES "public"."account"("id");



ALTER TABLE ONLY "public"."subscription_user_role"
    ADD CONSTRAINT "subscription_user_role_user_owner_id_fkey" FOREIGN KEY ("user_owner_id") REFERENCES "public"."account"("id");



ALTER TABLE ONLY "public"."account"
    ADD CONSTRAINT "user_id_fkey" FOREIGN KEY ("id") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."workspace_invite"
    ADD CONSTRAINT "workspace_invite_invited_by_fkey" FOREIGN KEY ("invited_by") REFERENCES "public"."account"("id");



ALTER TABLE ONLY "public"."workspace_invite"
    ADD CONSTRAINT "workspace_invite_user_owner_id_fkey" FOREIGN KEY ("user_owner_id") REFERENCES "public"."account"("id");



ALTER TABLE ONLY "public"."workspace_invite"
    ADD CONSTRAINT "workspace_invite_workspace_owner_id_fkey" FOREIGN KEY ("workspace_owner_id") REFERENCES "public"."workspace"("id");



ALTER TABLE ONLY "public"."workspace_member"
    ADD CONSTRAINT "workspace_member_invited_by_fkey" FOREIGN KEY ("invited_by") REFERENCES "public"."account"("id");



ALTER TABLE ONLY "public"."workspace_member"
    ADD CONSTRAINT "workspace_member_user_id_owner_id_fkey" FOREIGN KEY ("user_id_owner_id") REFERENCES "public"."account"("id");



ALTER TABLE ONLY "public"."workspace_member"
    ADD CONSTRAINT "workspace_member_workspace_owner_id_fkey" FOREIGN KEY ("workspace_owner_id") REFERENCES "public"."workspace"("id");



ALTER TABLE ONLY "public"."workspace"
    ADD CONSTRAINT "workspace_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."account"("id");



CREATE POLICY "Policy" ON "public"."workspace_invite" TO "authenticated", "anon" USING (true) WITH CHECK (true);



CREATE POLICY "Policy" ON "public"."workspace_member" TO "authenticated", "anon" USING (true) WITH CHECK (true);



CREATE POLICY "Policy ALL Security" ON "public"."account" TO "authenticated", "anon" USING (true) WITH CHECK (true);



CREATE POLICY "Policy ALL Security" ON "public"."onboarding" USING (true) WITH CHECK (true);



CREATE POLICY "Policy ALL Security" ON "public"."subscription" TO "authenticated", "anon" USING (true) WITH CHECK (true);



CREATE POLICY "Policy ALL Security" ON "public"."subscription_lineitems" TO "authenticated", "anon" USING (true) WITH CHECK (true);



CREATE POLICY "Policy All Security" ON "public"."workspace" TO "authenticated", "anon" USING (true) WITH CHECK (true);



ALTER TABLE "public"."account" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."onboarding" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "policy Account (SELECT)" ON "public"."account" FOR SELECT TO "authenticated", "anon" USING (true);



ALTER TABLE "public"."subscription" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."subscription_lineitems" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."subscription_user_role" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."workspace" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."workspace_invite" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."workspace_member" ENABLE ROW LEVEL SECURITY;




ALTER PUBLICATION "supabase_realtime" OWNER TO "postgres";


REVOKE USAGE ON SCHEMA "public" FROM PUBLIC;
GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";

























































































































































REVOKE ALL ON FUNCTION "kit"."add_current_user_to_new_account"() FROM PUBLIC;



REVOKE ALL ON FUNCTION "kit"."check_team_account"() FROM PUBLIC;



REVOKE ALL ON FUNCTION "kit"."get_storage_filename_as_uuid"("name" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "kit"."get_storage_filename_as_uuid"("name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "kit"."get_storage_filename_as_uuid"("name" "text") TO "service_role";



REVOKE ALL ON FUNCTION "kit"."handle_update_user_email"() FROM PUBLIC;



REVOKE ALL ON FUNCTION "kit"."prevent_account_owner_membership_delete"() FROM PUBLIC;



REVOKE ALL ON FUNCTION "kit"."prevent_memberships_update"() FROM PUBLIC;



REVOKE ALL ON FUNCTION "kit"."protect_account_fields"() FROM PUBLIC;



REVOKE ALL ON FUNCTION "kit"."set_slug_from_account_name"() FROM PUBLIC;



REVOKE ALL ON FUNCTION "kit"."setup_new_user"() FROM PUBLIC;



REVOKE ALL ON FUNCTION "kit"."slugify"("value" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "kit"."slugify"("value" "text") TO "service_role";
GRANT ALL ON FUNCTION "kit"."slugify"("value" "text") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."accept_invitation"("token" "text", "user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."accept_invitation"("token" "text", "user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_action_account_member"("target_team_account_id" "uuid", "target_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_action_account_member"("target_team_account_id" "uuid", "target_user_id" "uuid") TO "service_role";
GRANT ALL ON FUNCTION "public"."can_action_account_member"("target_team_account_id" "uuid", "target_user_id" "uuid") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."cancel_workspace"("c_workspace_owner_id" "uuid", "c_user_owner_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."cancel_workspace"("c_workspace_owner_id" "uuid", "c_user_owner_id" "uuid") TO "service_role";
GRANT ALL ON FUNCTION "public"."cancel_workspace"("c_workspace_owner_id" "uuid", "c_user_owner_id" "uuid") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."create_onboarding_and_workspace"("p_user_id" "uuid", "p_description" json, "p_user_type" character varying, "p_workspace_name" character varying) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."create_onboarding_and_workspace"("p_user_id" "uuid", "p_description" json, "p_user_type" character varying, "p_workspace_name" character varying) TO "service_role";
GRANT ALL ON FUNCTION "public"."create_onboarding_and_workspace"("p_user_id" "uuid", "p_description" json, "p_user_type" character varying, "p_workspace_name" character varying) TO "authenticated";



REVOKE ALL ON FUNCTION "public"."get_account_invitations"("account_slug" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_account_invitations"("account_slug" "text") TO "service_role";
GRANT ALL ON FUNCTION "public"."get_account_invitations"("account_slug" "text") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."get_account_members"("account_slug" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_account_members"("account_slug" "text") TO "service_role";
GRANT ALL ON FUNCTION "public"."get_account_members"("account_slug" "text") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."get_config"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_config"() TO "service_role";
GRANT ALL ON FUNCTION "public"."get_config"() TO "authenticated";



REVOKE ALL ON FUNCTION "public"."get_upper_system_role"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_upper_system_role"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."has_active_subscription"("target_account_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."has_active_subscription"("target_account_id" "uuid") TO "service_role";
GRANT ALL ON FUNCTION "public"."has_active_subscription"("target_account_id" "uuid") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."has_more_elevated_role"("target_user_id" "uuid", "target_account_id" "uuid", "role_name" character varying) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."has_more_elevated_role"("target_user_id" "uuid", "target_account_id" "uuid", "role_name" character varying) TO "service_role";
GRANT ALL ON FUNCTION "public"."has_more_elevated_role"("target_user_id" "uuid", "target_account_id" "uuid", "role_name" character varying) TO "authenticated";



REVOKE ALL ON FUNCTION "public"."has_permission"("user_id" "uuid", "account_id" "uuid", "permission_name" "public"."app_permissions") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."has_permission"("user_id" "uuid", "account_id" "uuid", "permission_name" "public"."app_permissions") TO "service_role";
GRANT ALL ON FUNCTION "public"."has_permission"("user_id" "uuid", "account_id" "uuid", "permission_name" "public"."app_permissions") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."has_role_on_account"("account_id" "uuid", "account_role" character varying) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."has_role_on_account"("account_id" "uuid", "account_role" character varying) TO "service_role";
GRANT ALL ON FUNCTION "public"."has_role_on_account"("account_id" "uuid", "account_role" character varying) TO "authenticated";



REVOKE ALL ON FUNCTION "public"."has_same_role_hierarchy_level"("target_user_id" "uuid", "target_account_id" "uuid", "role_name" character varying) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."has_same_role_hierarchy_level"("target_user_id" "uuid", "target_account_id" "uuid", "role_name" character varying) TO "service_role";
GRANT ALL ON FUNCTION "public"."has_same_role_hierarchy_level"("target_user_id" "uuid", "target_account_id" "uuid", "role_name" character varying) TO "authenticated";



REVOKE ALL ON FUNCTION "public"."insert_subscription"("s_sub_id" character varying, "s_inv_id" character varying, "s_cus_id" character varying, "s_id" character varying, "s_status" character varying, "s_user_id" "uuid", "s_created_at" timestamp without time zone, "s_updated_at" timestamp without time zone, "s_expires_at" timestamp without time zone, "l_item_id" character varying, "l_item_price_id" character varying, "l_item_product_id" character varying, "l_item_productname" character varying, "l_item_created_at" timestamp without time zone, "l_item_updated_at" timestamp without time zone) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."insert_subscription"("s_sub_id" character varying, "s_inv_id" character varying, "s_cus_id" character varying, "s_id" character varying, "s_status" character varying, "s_user_id" "uuid", "s_created_at" timestamp without time zone, "s_updated_at" timestamp without time zone, "s_expires_at" timestamp without time zone, "l_item_id" character varying, "l_item_price_id" character varying, "l_item_product_id" character varying, "l_item_productname" character varying, "l_item_created_at" timestamp without time zone, "l_item_updated_at" timestamp without time zone) TO "service_role";



REVOKE ALL ON FUNCTION "public"."is_account_owner"("account_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."is_account_owner"("account_id" "uuid") TO "service_role";
GRANT ALL ON FUNCTION "public"."is_account_owner"("account_id" "uuid") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."is_account_team_member"("target_account_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."is_account_team_member"("target_account_id" "uuid") TO "service_role";
GRANT ALL ON FUNCTION "public"."is_account_team_member"("target_account_id" "uuid") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."is_set"("field_name" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."is_set"("field_name" "text") TO "service_role";
GRANT ALL ON FUNCTION "public"."is_set"("field_name" "text") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."is_team_member"("account_id" "uuid", "user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."is_team_member"("account_id" "uuid", "user_id" "uuid") TO "service_role";
GRANT ALL ON FUNCTION "public"."is_team_member"("account_id" "uuid", "user_id" "uuid") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."team_account_workspace"("account_slug" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."team_account_workspace"("account_slug" "text") TO "service_role";
GRANT ALL ON FUNCTION "public"."team_account_workspace"("account_slug" "text") TO "authenticated";



REVOKE ALL ON FUNCTION "public"."transfer_team_account_ownership"("target_account_id" "uuid", "new_owner_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."transfer_team_account_ownership"("target_account_id" "uuid", "new_owner_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."trigger_set_timestamps"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."trigger_set_timestamps"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."trigger_set_user_tracking"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."trigger_set_user_tracking"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."workspace_approved"("w_user_owner_id" "uuid", "w_workspace_owner_id" "uuid", "w_invited_by" "uuid", "w_workspace_status" "public"."workspace_status", "w_role" "public"."workspace_role", "w_joined" timestamp without time zone) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."workspace_approved"("w_user_owner_id" "uuid", "w_workspace_owner_id" "uuid", "w_invited_by" "uuid", "w_workspace_status" "public"."workspace_status", "w_role" "public"."workspace_role", "w_joined" timestamp without time zone) TO "service_role";
GRANT ALL ON FUNCTION "public"."workspace_approved"("w_user_owner_id" "uuid", "w_workspace_owner_id" "uuid", "w_invited_by" "uuid", "w_workspace_status" "public"."workspace_status", "w_role" "public"."workspace_role", "w_joined" timestamp without time zone) TO "authenticated";


















GRANT ALL ON TABLE "public"."account" TO "anon";
GRANT ALL ON TABLE "public"."account" TO "authenticated";
GRANT ALL ON TABLE "public"."account" TO "service_role";



GRANT ALL ON TABLE "public"."onboarding" TO "anon";
GRANT ALL ON TABLE "public"."onboarding" TO "authenticated";
GRANT ALL ON TABLE "public"."onboarding" TO "service_role";



GRANT ALL ON SEQUENCE "public"."onboarding_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."onboarding_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."onboarding_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."subscription" TO "anon";
GRANT ALL ON TABLE "public"."subscription" TO "authenticated";
GRANT ALL ON TABLE "public"."subscription" TO "service_role";



GRANT ALL ON TABLE "public"."subscription_lineitems" TO "anon";
GRANT ALL ON TABLE "public"."subscription_lineitems" TO "authenticated";
GRANT ALL ON TABLE "public"."subscription_lineitems" TO "service_role";



GRANT ALL ON TABLE "public"."subscription_user_role" TO "anon";
GRANT ALL ON TABLE "public"."subscription_user_role" TO "authenticated";
GRANT ALL ON TABLE "public"."subscription_user_role" TO "service_role";



GRANT ALL ON TABLE "public"."workspace" TO "anon";
GRANT ALL ON TABLE "public"."workspace" TO "authenticated";
GRANT ALL ON TABLE "public"."workspace" TO "service_role";



GRANT ALL ON TABLE "public"."workspace_invite" TO "anon";
GRANT ALL ON TABLE "public"."workspace_invite" TO "authenticated";
GRANT ALL ON TABLE "public"."workspace_invite" TO "service_role";



GRANT ALL ON TABLE "public"."workspace_member" TO "anon";
GRANT ALL ON TABLE "public"."workspace_member" TO "authenticated";
GRANT ALL ON TABLE "public"."workspace_member" TO "service_role";









ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" REVOKE ALL ON FUNCTIONS FROM PUBLIC;



























