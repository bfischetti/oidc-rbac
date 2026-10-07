# Roles travel in the Access Token; each Resource Server maps them to Permissions

The OP only knows Users and Roles and puts `roles` in the Access Token. Each Resource Server owns its own Role-to-Permission table and checks Permissions locally after verifying the JWT against the OP's JWKS, with no runtime call to the OP. This follows the Keycloak/Entra pattern. We rejected embedding resolved permissions in the token (Auth0 style), which centralises policy at the OP, and having Resource Servers query the OP for the mapping, which adds a runtime dependency.
