# ms-user-experience

Microservicio de **preferencias e interacciones del usuario** (puerto `3006`,
esquema PostgreSQL `user_experience`).

Dueño de los datos de interaccion: preferencias, favoritos, ratings de ambientes
y busquedas. No posee usuarios, ambientes ni variables: los referencia por UUID.

## Contrato

`07-api/contracts/openapi/` (repositorio de documentacion, por definir).

## Arranque local

Requiere PostgreSQL en `localhost:5432` (BD `eduaircontrol_user_experience`). La
autenticación usa RS256 vía el JWKS de `ms-security` (ADR-006): no hay secreto local,
el token lo emite ms-security.

```bash
# local (necesita PostgreSQL con la BD eduaircontrol_user_experience)
POSTGRES_USER=user_experience_user POSTGRES_PASSWORD=user_experience_pass ./mvnw spring-boot:run

# o stack del servicio (app + PostgreSQL)
docker compose up --build
```

## Verificacion

```bash
curl http://localhost:3006/health
```
