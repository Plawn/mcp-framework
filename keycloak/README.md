# Realm Keycloak `mcp` — mode *resource server*

`mcp-realm.json` est un export de realm Keycloak 26.x prêt à importer. Il décrit
l'autorité d'autorisation attendue par `mcp-framework` quand celui-ci tourne en
`MCP_TOKEN_MODE=resource_server` : le framework ne proxyfie plus rien, il se
contente de valider localement les JWT émis par ce realm.

Ce fichier est aussi la fixture de `tests/oauth_lifecycle_rmcp.rs` : le harness
le charge, en patche deux valeurs à chaud (durée de vie de l'access token,
audience) et l'importe dans un conteneur Keycloak éphémère. Toute modification
ici est donc immédiatement couverte par ces tests.

## Import

```bash
# Local, jetable
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_HOSTNAME_STRICT=false \
  -v "$PWD/keycloak:/opt/keycloak/data/import:ro" \
  quay.io/keycloak/keycloak:26.3 start-dev --import-realm

# Sur une instance existante
kcadm.sh create realms -f keycloak/mcp-realm.json
```

L'import doit se terminer sans ligne `Referenced client scope '...' doesn't
exist. Ignoring` : c'est le symptôme d'un `clientScopes` incomplet (voir plus
bas).

## Contenu

### Client `mcp-client` — public, PKCE S256

`publicClient: true`, flux standard uniquement (`directAccessGrantsEnabled:
false`, pas d'implicite, pas de device flow), `pkce.code.challenge.method =
S256` — donc PKCE obligatoire, ce que la spec MCP exige d'un client public.

`redirectUris` couvre deux familles :

- **CLI / loopback (RFC 8252)** — `http://127.0.0.1/*` et `http://localhost/*`.
  Le joker couvre le port éphémère : un client qui écoute sur
  `http://127.0.0.1:53127/callback` matche.
- **Clients hébergés** — Claude (`https://claude.ai/api/mcp/auth_callback`,
  `https://claude.com/api/mcp/auth_callback`) et Cursor
  (`cursor://anysphere.cursor-retrieval/oauth/user-*/callback`,
  `https://cursor.com/api/auth/callback`).

> **À confirmer.** Les URI des clients hébergés sont relevées sur les versions
> actuelles de Claude et Cursor ; ni l'une ni l'autre n'est un contrat
> versionné. À revérifier contre le client réel avant une mise en production, et
> à retirer si le déploiement ne vise que des clients CLI.

`post.logout.redirect.uris` reprend les mêmes origines (séparateur `##`, la
convention Keycloak pour une valeur multiple dans un attribut).

### Scope `mcp-audience` — l'audience du serveur MCP

Keycloak n'implémente pas le paramètre `resource` de la RFC 8707. Le
contournement officiel est un *audience mapper* : un mapper de protocole qui
écrit en dur l'URL canonique du serveur MCP dans le `aud` de l'access token.

Le scope est un **default client scope** de `mcp-client`, avec
`include.in.token.scope: false` — l'audience est injectée sans que
`mcp-audience` apparaisse dans le claim `scope`, qui reste ce que le client a
effectivement demandé.

La valeur livrée est `https://mcp.example.com/mcp`. **Elle est à substituer par
déploiement** : c'est exactement la valeur que le serveur MCP doit annoncer dans
`OAUTH_EXPECTED_AUDIENCE`. Les deux doivent correspondre au caractère près,
sinon toutes les requêtes répondent `401`.

> **Écart avec la fiche 924.** Le mapper utilisé est `oidc-audience-mapper`, pas
> `oidc-hardcoded-audience-mapper`. Ce dernier n'existe pas dans Keycloak 26.3 :
> `GET /admin/serverinfo` ne liste que `oidc-audience-mapper` et
> `oidc-audience-resolve-mapper`. Un `protocolMapper` inconnu est accepté
> silencieusement à l'import et n'injecte alors rien du tout — d'où une
> vérification explicite du `aud` dans le harness.

### Scopes `mcp:tools` et `mcp:resources`

Scopes optionnels, alignés sur le `scopes_supported` que le framework publie
dans sa métadonnée RFC 8414 (`src/auth/metadata.rs`). Ils ne portent aucun
mapper : ce sont des étiquettes, à exploiter côté serveur via un
`AccessValidator` ou un `CapabilityFilter` lisant le claim `scope`.

### Client scopes intégrés

`clientScopes` contient aussi les scopes standards de Keycloak (`acr`, `basic`,
`email`, `profile`, `roles`, `web-origins`, `address`, `microprofile-jwt`,
`phone`, `offline_access`). Ce n'est pas de la redondance : **dès qu'un export
fournit `clientScopes`, Keycloak ne crée plus les scopes par défaut**. Les
omettre casse chaque référence à un scope standard dans `defaultClientScopes` /
`optionalClientScopes`. `defaultDefaultClientScopes` et
`defaultOptionalClientScopes` fixent ce que reçoit tout nouveau client — y
compris ceux créés par DCR.

### Politiques d'enregistrement dynamique (DCR)

`components` porte les *Client Registration Policies* sous
`org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy`, en
deux sous-types (`anonymous` et `authenticated`) :

| Politique | Rôle |
|---|---|
| `trusted-hosts` | restreint les hôtes autorisés à s'enregistrer et les `redirect_uri` acceptés |
| `allowed-client-templates` | limite les client scopes qu'un client enregistré peut réclamer |
| `allowed-protocol-mappers` | liste blanche de mappers — empêche un client enregistré de se fabriquer des claims |
| `max-clients` | plafond de clients (200) |
| `consent-required` | force le consentement pour les clients anonymes |

Le proxy `/oauth/register` du framework reste le point d'entrée : le endpoint
`clients-registrations/openid-connect` de Keycloak ne renvoie aucun en-tête CORS,
donc un client MCP navigateur ne peut pas l'appeler directement.

> **À confirmer.** `trusted-hosts` liste `mcp.example.com`, `localhost` et
> `127.0.0.1`. À aligner sur le nom d'hôte public réel avant mise en production.

### Durées de vie

| Réglage | Valeur | Pourquoi |
|---|---|---|
| `accessTokenLifespan` | 600 s | 10 min — dans la fourchette 5-15 min recommandée |
| `revokeRefreshToken` | `true` | rotation du refresh token |
| `refreshTokenMaxReuse` | 0 | aucune réutilisation : détection de vol |
| `ssoSessionIdleTimeout` | 30 j | une connexion MCP peut rester ouverte longtemps |
| `ssoSessionMaxLifespan` | 90 j | plafond absolu |
| `clientSessionIdleTimeout` / `clientSessionMaxLifespan` | 0 | héritent de la session SSO |
| `offlineSessionIdleTimeout` | 30 j | pour les clients demandant `offline_access` |

> **À confirmer.** Ces valeurs sont *proposées*, pas mesurées. Elles arbitrent
> entre confort (une session MCP qui survit à un week-end) et exposition (un
> refresh token volé reste utilisable aussi longtemps). Le harness les écrase :
> il ramène `accessTokenLifespan` à quelques secondes pour rendre l'expiration
> observable en test.

> **Risque : la rotation des refresh tokens casse le mode `passthrough`.** En
> passthrough, le client et le serveur détiennent le *même* refresh token ; à la
> première rotation côté serveur, la copie du client devient invalide. N'activez
> `revokeRefreshToken` qu'**après** être passé en
> `MCP_TOKEN_MODE=resource_server`, où seul le client détient le grant.

### Utilisateurs de test

`alice` / `alice` et `bob` / `bob`, mots de passe non temporaires, e-mails
vérifiés. Ils existent pour les tests d'intégration (deux principals distincts
permettent de vérifier l'isolation des identités de session). **À retirer de
tout realm non jetable.**

### `sslRequired: "none"`

Nécessaire pour parler HTTP en local et en conteneur. **À remettre à
`"external"` (le défaut Keycloak) dans un realm réel.**

## Configuration correspondante du serveur MCP

```bash
MCP_TOKEN_MODE=resource_server
OAUTH_UNKNOWN_TOKEN_VALIDATION=jwks
OAUTH_EXPECTED_AUDIENCE=https://mcp.example.com/mcp   # = valeur du mapper d'audience
OAUTH_ISSUER_URL=https://<keycloak>/realms/mcp
OAUTH_CLIENT_ID=mcp-client
```

`OAUTH_EXPECTED_AUDIENCE` est **obligatoire** dans ce mode : le framework refuse
de démarrer sans. Un `aud` non contraint reviendrait à accepter tout token que
l'émetteur a signé, y compris un token destiné à un autre service — le *confused
deputy* que la RFC 8707 et la spec MCP demandent à un resource server de
refuser.

`OAUTH_UNKNOWN_TOKEN_VALIDATION=jwks` est de toute façon la seule valeur
utilisable ici : le défaut `jwks_then_introspection` est ramené à `jwks` au
démarrage (avec un `warn`), et `introspection` / `reject` sont des erreurs de
démarrage.

> **Risque : l'issuer annoncé doit être l'URL publique.** Keycloak dérive
> `issuer` de `KC_HOSTNAME`. Derrière un Swarm / un reverse proxy, un hostname
> interne se retrouve dans le `iss` des tokens et dans la métadonnée de
> découverte — le client MCP compare alors ce qu'il a découvert à ce qu'il reçoit
> et échoue (`AuthorizationServerIssuerMismatch` côté rmcp). `KC_HOSTNAME` doit
> valoir l'URL publique, et `OAUTH_ISSUER_URL` la même chose.

## Hors périmètre

L'échange de tokens (RFC 8693) pour appeler une API en amont. Un token émis pour
ce serveur MCP ne doit pas être transmis à un autre service ; un consommateur
qui en a besoin fait l'échange lui-même dans son handler d'outil, à partir de
`ctx.token()`.
