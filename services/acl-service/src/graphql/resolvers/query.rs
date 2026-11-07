use std::sync::Arc;

use async_graphql::{Context, Object, Result};
use axum::Extension;
use hyper::{
    HeaderMap, StatusCode,
    header::{AUTHORIZATION, COOKIE},
};
use lib::utils::{
    api_responses::synthesize_graphql_response,
    custom_error::ExtendedError,
    models::{AuthStatus, AuthorizationConstraint},
};
use surrealdb::{Surreal, engine::remote::ws::Client};

use crate::{
    graphql::schemas::{
        role::{Department, Organization, Permission, Resource, SystemRole},
        shared::GraphQLApiResponse,
        user::{FetchUsersQueryFilters, User},
    },
    utils::auth::{confirm_authentication, confirm_authorization},
};

pub struct Query;

#[Object]
impl Query {
    /// Fetches a list of users based on hierarchy(default) or the provided filters.
    async fn fetch_users(
        &self,
        ctx: &Context<'_>,
        filters: Option<FetchUsersQueryFilters>,
    ) -> Result<GraphQLApiResponse<Vec<User>>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let authenticated = confirm_authentication(db, ctx).await?;

        let authenticated_ref = &authenticated;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["read:user".into()],
        };

        let authorized =
            confirm_authorization(db, authenticated_ref, &authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut fetch_users_query = db
            .query(
                r#"
                LET $user = type::record('user', $user_id);
                LET $org = type::record('organization', $filters.organization_id);
                LET $dept = type::record('department', $filters.department_id);
                LET $role = type::record('role', $filters.role_id);

                LET $status = $filters.status;
                LET $org_id = $filters.organization_id;
                LET $dept_id = $filters.department_id;
                LET $role_id = $filters.role_id;

                <array> <set> array::flatten(
                    [
                        (
                            SELECT *
                            FROM user
                            WHERE ->assigned->role->is_under->(organization WHERE created_by = $user)
                        ),
                        (
                            SELECT *
                            FROM user
                            WHERE ->assigned->role->is_under->(department WHERE created_by = $user)
                        ),
                        (
                            SELECT *
                            FROM user
                            WHERE @.{..} (->assigned->role->is_under->department)->is_under->(organization WHERE created_by = $user)
                        ),
                        (
                            SELECT *
                            FROM user
                            WHERE @.{..} (->assigned->role->is_under->department)->is_under->(department WHERE created_by = $user)
                        ),
                        (
                            SELECT *
                            FROM user
                            WHERE ->assigned->(role WHERE created_by = $user)
                        ),
                    ]
                ).filter(
                    |$u| {
                        IF $status != NONE {
                            $u.status == $status;
                        } ELSE {
                            true;
                        };
                    }
                ).filter(
                    |$u| {
                        IF $org_id != NONE {
                            SELECT *
                            FROM ONLY $u
                            WHERE
                                ->assigned->role->is_under->(organization WHERE id = $org)
                                OR @.{..} (->assigned->role->is_under->department)->is_under->(organization WHERE id = $org);
                        } ELSE {
                            true;
                        };
                    }
                ).filter(
                    |$u| {
                        IF $dept_id != NONE {
                            SELECT *
                            FROM ONLY $u
                            WHERE
                                ->assigned->role->is_under->(department WHERE id = $dept)
                                OR @.{..} (->assigned->role->is_under->department)->is_under->(department WHERE id = $dept);
                        } ELSE {
                            true;
                        };
                    }
                ).filter(
                    |$u| {
                        IF $role_id != NONE {
                            $u->assigned->(role WHERE id = $role);
                        } ELSE {
                            true;
                        };
                    }
                );
                "#
            )
            .bind(("user_id", authenticated_ref.sub.to_owned()))
            .bind(("filters", filters))
            .await
            .map_err(|e| {
            tracing::error!("Error fetching users: {}", e);
            ExtendedError::new("Error fetching users", StatusCode::BAD_REQUEST.as_str()).build()
        })?;

        let response: Vec<User> = fetch_users_query.take(8).map_err(|e| {
            tracing::error!("Users deserialization error: {}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let api_response = synthesize_graphql_response(ctx, &response, Some(authenticated_ref))
            .ok_or_else(|| {
                tracing::error!("Failed to synthesize response!");
                ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        Ok(api_response.into())
    }

    /// Fetch a single user by ID. Respects hierarchy and permissions.
    async fn fetch_single_user(
        &self,
        ctx: &Context<'_>,
        user_id: String,
    ) -> Result<GraphQLApiResponse<User>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        match confirm_authentication(db, ctx).await {
            Ok(authenticated) => {
                let authenticated_ref = &authenticated;

                let authorization_constraint = AuthorizationConstraint {
                    permissions: vec!["read:user".into()],
                };

                let authorized =
                    confirm_authorization(db, &authenticated, &authorization_constraint).await?;
                let is_owner = authenticated_ref.sub.to_owned() == user_id;

                if !authorized && !is_owner {
                    return Err(
                        ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build(),
                    );
                }

                let mut user_query = db
                    .query(
                        "
                        LET $user = type::record('user', $user_id);
                        (SELECT * FROM ONLY $user LIMIT 1);

                        LET $auth_user = type::record('user', $auth_sub);
                        (SELECT * FROM ONLY $user WHERE (->assigned->(role WHERE created_by = $auth_user) OR ->assigned->role->is_under->(organization WHERE created_by = $auth_user) OR ->assigned->role->is_under->(department WHERE created_by = $auth_user) OR @.{..}(->assigned->role->is_under->department)->is_under->(organization WHERE created_by = $auth_user) OR @.{..}(->assigned->role->is_under->department)->is_under->(department WHERE created_by = $auth_user)));
                        "
                    )
                    .bind(("user_id", user_id))
                    .bind(("auth_sub", authenticated_ref.sub.to_owned()))
                    .await.map_err(|e| {
                    tracing::error!("Error fetching user: {}", e);
                    ExtendedError::new("Error fetching user", StatusCode::BAD_REQUEST.as_str())
                        .build()
                })?;

                let user: Option<User> = if is_owner {
                    user_query.take(1).map_err(|e| {
                        tracing::error!("User deserialization error: {}", e);
                        ExtendedError::new(
                            "Server Error",
                            StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                        )
                        .build()
                    })?
                } else {
                    user_query.take(3).map_err(|e| {
                        tracing::error!("User deserialization error: {}", e);
                        ExtendedError::new(
                            "Server Error",
                            StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                        )
                        .build()
                    })?
                };

                match user {
                    Some(user) => {
                        let api_response =
                            synthesize_graphql_response(ctx, &user, Some(authenticated_ref))
                                .ok_or_else(|| {
                                    tracing::error!("Failed to synthesize response!");
                                    ExtendedError::new(
                                        "Bad Request",
                                        StatusCode::BAD_REQUEST.as_str(),
                                    )
                                    .build()
                                })?;

                        Ok(api_response.into())
                    }
                    None => Err(ExtendedError::new(
                        "User not found",
                        StatusCode::NOT_FOUND.as_str(),
                    )
                    .build()),
                }
            }
            Err(_e) => {
                let mut user_query = db
                    .query(
                        "
                        LET $user_record = type::record('user', $user_id);
                        LET $found_user = (SELECT * OMIT password, user_name, status FROM ONLY user WHERE id = $user_record OR oauth_user_id = $user_id LIMIT 1);
                        RETURN $found_user;
                        "
                    )
                    .bind(("user_id", user_id))
                    .await
                    .map_err(|e| {
                    tracing::error!("Error fetching user: {}", e);
                    ExtendedError::new("Error fetching user", StatusCode::BAD_REQUEST.as_str()).build()
                })?;

                let user: Option<User> = user_query.take(2).map_err(|e| {
                    tracing::error!("User deserialization error: {}", e);
                    ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str())
                        .build()
                })?;

                match user {
                    Some(user) => {
                        let api_response = synthesize_graphql_response(ctx, &user, None)
                            .ok_or_else(|| {
                                tracing::error!("Failed to synthesize response!");
                                ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str())
                                    .build()
                            })?;
                        return Ok(api_response.into());
                    }
                    None => {
                        return Err(ExtendedError::new(
                            "User not found",
                            StatusCode::NOT_FOUND.as_str(),
                        )
                        .build());
                    }
                }
            }
        }
    }

    /// Fetch site owner basic info.
    async fn fetch_site_owner_info(&self, ctx: &Context<'_>) -> Result<GraphQLApiResponse<User>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let mut user_query = db
            .query(
                "
                (SELECT * OMIT password, user_name, status, phone, oauth_client, oauth_user_id FROM ONLY user WHERE ->assigned->(role WHERE is_super_admin) LIMIT 1)
                "
            )
            .await
            .map_err(|e| {
            tracing::error!("Error fetching user: {}", e);
            ExtendedError::new("Error fetching user", StatusCode::BAD_REQUEST.as_str()).build()
        })?;

        let user: Option<User> = user_query.take(0).map_err(|e| {
            tracing::error!("User deserialization error: {}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        match user {
            Some(user) => {
                let api_response =
                    synthesize_graphql_response(ctx, &user, None).ok_or_else(|| {
                        tracing::error!("Failed to synthesize response!");
                        ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
                    })?;

                return Ok(api_response.into());
            }
            None => {
                return Err(
                    ExtendedError::new("User not found", StatusCode::NOT_FOUND.as_str()).build(),
                );
            }
        }
    }

    async fn check_auth(&self, ctx: &Context<'_>) -> Result<GraphQLApiResponse<AuthStatus>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let auth_status = confirm_authentication(db, ctx).await.map_err(|e| {
            tracing::error!("Error confirming authentication: {:?}", e);
            ExtendedError::new("Unauthorized!", StatusCode::UNAUTHORIZED.as_str()).build()
        })?;

        let auth_status_ref = &auth_status;

        let api_response = synthesize_graphql_response(ctx, &auth_status, Some(auth_status_ref))
            .ok_or_else(|| {
                tracing::error!("Failed to synthesize response!");
                ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        Ok(api_response.into())
    }

    /// Fetches system roles assigned to a given user or under organization created by the user or under department created by the user
    async fn fetch_system_roles(
        &self,
        ctx: &Context<'_>,
        user_id: Option<String>,
    ) -> Result<GraphQLApiResponse<Vec<SystemRole>>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let authenticated = confirm_authentication(db, ctx).await?;
        let authenticated_ref = &authenticated;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["read:role".into()],
        };

        let authorized =
            confirm_authorization(db, authenticated_ref, &authorization_constraint).await?;

        match user_id {
            // No explicit user_id: return the roles owned by the caller.
            None => {
                if !authorized {
                    return Err(
                        ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build(),
                    );
                }

                let mut query = db
                    .query(
                        "
                        LET $user = type::record('user', $user_id);

                        LET $roles = <array><set>array::flatten([
                           (SELECT * FROM role WHERE ->is_under->(organization WHERE created_by = $user)),
                           (SELECT * FROM role WHERE ->is_under->(department WHERE created_by = $user)),
                           (SELECT * FROM role WHERE @.{..}(->is_under->department)->is_under->(organization WHERE created_by = $user)),
                           (SELECT * FROM role WHERE @.{..}(->is_under->department)->is_under->(department WHERE created_by = $user))
                        ]);
                        RETURN $roles;
                        ",
                    )
                    .bind(("user_id", authenticated_ref.sub.to_owned()))
                    .await
                    .map_err(|e| {
                        tracing::error!("Error fetching roles: {}", e);
                        ExtendedError::new("Error fetching roles", StatusCode::BAD_REQUEST.as_str())
                            .build()
                    })?;

                let response: Vec<SystemRole> = query.take(2).map_err(|e| {
                    tracing::error!("SystemRole deserialization error: {}", e);
                    ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str())
                        .build()
                })?;

                let api_response =
                    synthesize_graphql_response(ctx, &response, Some(authenticated_ref))
                        .ok_or_else(|| {
                            tracing::error!("Failed to synthesize response!");
                            ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str())
                                .build()
                        })?;

                Ok(api_response.into())
            }

            // Explicit user_id: admin, or the user themselves, can read.
            Some(user_id) => {
                if user_id != authenticated.sub && !authorized {
                    return Err(
                        ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build(),
                    );
                }

                let mut query = db
                    .query(
                        "
                        LET $user = type::record('user', $user_id);

                        LET $roles = (SELECT ->assigned->role.* AS roles FROM ONLY $user)['roles'];
                        RETURN $roles;
                        ",
                    )
                    .bind(("user_id", user_id))
                    .await
                    .map_err(|e| {
                        tracing::error!("Error fetching roles: {}", e);
                        ExtendedError::new("Error fetching roles", StatusCode::BAD_REQUEST.as_str())
                            .build()
                    })?;

                let response: Vec<SystemRole> = query.take(2).map_err(|e| {
                    tracing::error!("SystemRole deserialization error: {}", e);
                    ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str())
                        .build()
                })?;

                let api_response =
                    synthesize_graphql_response(ctx, &response, Some(authenticated_ref))
                        .ok_or_else(|| {
                            tracing::error!("Failed to synthesize response!");
                            ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str())
                                .build()
                        })?;

                Ok(api_response.into())
            }
        }
    }

    /// Fetch all permissions that the logged in user's current role is granted.
    async fn fetch_current_role_permissions(
        &self,
        ctx: &Context<'_>,
    ) -> Result<GraphQLApiResponse<Vec<Permission>>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let authenticated = confirm_authentication(db, ctx).await?;

        let authenticated_ref = &authenticated;

        let mut fetch_role_permissions_query = db
            .query(
                "
            LET $user = type::record('user', $user_id);

            LET $permissions = (SELECT *, resource[*] FROM permission WHERE <-granted<-(role WHERE role_name = $current_role_name)<-assigned<-(user WHERE id = $user));
            RETURN $permissions;
            ",
            )
            .bind(("user_id", authenticated_ref.sub.to_owned()))
            .bind(("current_role_name", authenticated_ref.current_role.to_owned()))
            .await
            .map_err(|e| {
                tracing::error!("Error fetching permissions: {}", e);
                ExtendedError::new("Error fetching permissions", StatusCode::BAD_REQUEST.as_str())
                    .build()
            })?;

        let response: Vec<Permission> = fetch_role_permissions_query.take(2).map_err(|e| {
            tracing::error!("SystemRole deserialization error: {}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let api_response = synthesize_graphql_response(ctx, &response, Some(authenticated_ref))
            .ok_or_else(|| {
                tracing::error!("Failed to synthesize response!");
                ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        Ok(api_response.into())
    }

    /// Fetch all organizations where the user is assigned an admin role and is allowed to create roles/assign roles/create a department
    async fn fetch_organizations(
        &self,
        ctx: &Context<'_>,
    ) -> Result<GraphQLApiResponse<Vec<Organization>>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let authenticated = confirm_authentication(db, ctx).await?;

        let authenticated_ref = &authenticated;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["read:organization".into()],
        };

        let authorized =
            confirm_authorization(db, &authenticated, &authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut fetch_user_orgs_query = db
            .query(
                "
                LET $user = type::record('user', $user_id);

                LET $organizations = <array><set> array::flatten([
                   	(SELECT * FROM organization WHERE created_by = $user),
                   	(SELECT * FROM organization WHERE <-is_under<-(role WHERE (is_admin OR is_super_admin) AND ->granted->permission.name CONTAINSANY [
                  		'write:department',
                  		'write:role',
                  		'assign:role'
                   	])<-assigned<-(user WHERE id = $user))
                ]);
                RETURN $organizations;
                ",
            )
            .bind(("user_id", authenticated_ref.sub.to_owned()))
            .await
            .map_err(|e| {
                tracing::error!("Error fetching organizations: {}", e);
                ExtendedError::new("Error fetching organizations", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        let response: Vec<Organization> = fetch_user_orgs_query.take(2).map_err(|e| {
            tracing::error!("Organization deserialization error: {}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let api_response = synthesize_graphql_response(ctx, &response, Some(authenticated_ref))
            .ok_or_else(|| {
                tracing::error!("Failed to synthesize response!");
                ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        Ok(api_response.into())
    }

    /// Fetch all departments where the user is assigned an admin role and is allowed to create roles/assign roles/create a department
    async fn fetch_departments(
        &self,
        ctx: &Context<'_>,
    ) -> Result<GraphQLApiResponse<Vec<Department>>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let authenticated = confirm_authentication(db, ctx).await?;

        let authenticated_ref = &authenticated;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["read:department".into()],
        };

        let authorized =
            confirm_authorization(db, &authenticated, &authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut fetch_user_departments_query = db
            .query(
                "
                LET $user = type::record('user', $user_id);

                LET $departments = <array><set>array::flatten([
                   	(SELECT * FROM department WHERE created_by = $user),
                   	(SELECT * FROM department WHERE <-is_under<-(role WHERE (is_admin OR is_super_admin) AND ->granted->permission.name CONTAINSANY [
                  		'write:department',
                  		'write:role',
                  		'assign:role'
                   	])<-assigned<-(user WHERE id = $user)),
                    (SELECT * FROM department WHERE @.{..}(->is_under)->(organization WHERE created_by = $user)),
                    (SELECT * FROM department WHERE @.{..}(->is_under)->(department WHERE created_by = $user)),
                ]).filter(|$v| $v);
                RETURN $departments;
                ",
            )
            .bind(("user_id", authenticated_ref.sub.to_owned()))
            .await
            .map_err(|e| {
                tracing::error!("Error fetching departments: {}", e);
                ExtendedError::new("Error fetching departments", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        let response: Vec<Department> = fetch_user_departments_query.take(2).map_err(|e| {
            tracing::error!("Department deserialization error: {}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let api_response = synthesize_graphql_response(ctx, &response, Some(authenticated_ref))
            .ok_or_else(|| {
                tracing::error!("Failed to synthesize response!");
                ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        Ok(api_response.into())
    }

    /// Fetch all resources.
    async fn fetch_resources(
        &self,
        ctx: &Context<'_>,
    ) -> Result<GraphQLApiResponse<Vec<Resource>>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let authenticated = confirm_authentication(db, ctx).await?;

        let authenticated_ref = &authenticated;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["read:resource".into()],
        };

        let authorized =
            confirm_authorization(db, &authenticated, &authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut fetch_role_permissions_resources_query = db
            .query(
                "
            LET $user = type::record('user', $user_id);

            LET $resources =(SELECT * FROM resource);
            RETURN $resources;
            ",
            )
            .bind(("user_id", authenticated_ref.sub.to_owned()))
            .bind((
                "current_role_name",
                authenticated_ref.current_role.to_owned(),
            ))
            .await
            .map_err(|e| {
                tracing::error!("Error fetching resources: {}", e);
                ExtendedError::new("Error fetching resources", StatusCode::BAD_REQUEST.as_str())
                    .build()
            })?;

        let response: Vec<Resource> =
            fetch_role_permissions_resources_query
                .take(2)
                .map_err(|e| {
                    tracing::error!("SystemRole deserialization error: {}", e);
                    ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str())
                        .build()
                })?;

        let api_response = synthesize_graphql_response(ctx, &response, Some(authenticated_ref))
            .ok_or_else(|| {
                tracing::error!("Failed to synthesize response!");
                ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        Ok(api_response.into())
    }
}
