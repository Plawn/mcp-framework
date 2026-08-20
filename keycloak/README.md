# Realm Keycloak `mcp` — mode *resource server*

`mcp-realm.json` est un export de realm Keycloak 26.x prêt à importer. Il décrit
l'autorité d'autorisation attendue par `mcp-framework` quand celui-ci tourne en
`MCP_TOKEN_MODE=resource_server` : le framework ne proxyfie plus rien, il se
contente de valider localement les JWT émis par ce realm.

Ce fichier est aussi la fixture de `tests/oauth_lifecycle_rmcp.rs` : le harness
le charge, le patche à chaud et l'importe dans un conteneur Keycloak éphémère.
Toute modification ici est donc immédiatement couverte par ces tests.

Le realm livré n'est **pas** une fixture de test : il exige TLS et ne contient
aucun utilisateur. Tout ce dont un test a besoin et qu'un realm réel ne doit pas
porter est injecté par le harness (`write_patched_realm`), pas par ce fichier :
durée de vie de l'access token, audience, `sslRequired: none`, les utilisateurs
`alice` / `bob`. Les politiques d'enregistrement dynamique, elles, sont
exercées **telles que livrées**.

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

`fullScopeAllowed: false`. Avec `true`, le client hérite de *tous* les rôles du
royaume : les tokens portent le `realm_access` complet de l'utilisateur, y
compris des rôles qui ne concernent en rien le serveur MCP, et un token volé
devient beaucoup plus intéressant. Ce que le client doit réellement obtenir
passe par les *scope mappings* de ses client scopes — c'est le cas de
`offline_access`, dont le rôle royaume homonyme est porté par le client scope
que Keycloak crée lui-même (voir plus bas), donc la demande `offline_access`
que rmcp ajoute continue de passer. Un déploiement dont un `AccessValidator`
lit un rôle métier doit l'attacher explicitement au client ou à un client
scope, pas rouvrir le scope complet.

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

Scopes optionnels, à exploiter côté serveur via un `AccessValidator` ou un
`CapabilityFilter` lisant le claim `scope`. Pour qu'un client les demande, il
faut que le serveur MCP les annonce : la métadonnée RFC 8414 / RFC 9728 publie
désormais les scopes **configurés** (`OAUTH_SCOPES`), donc le déploiement doit
poser

```bash
OAUTH_SCOPES=openid,profile,email,mcp:tools,mcp:resources
```

sans quoi `scopes_supported` reste `openid profile email` et aucun client ne
réclamera jamais ces deux scopes.

Ils portent **le même mapper d'audience** que `mcp-audience`, et ce n'est pas
décoratif : voir « Enregistrement dynamique » plus bas. Un client enregistré
dynamiquement perd les default client scopes du realm — donc `mcp-audience` —
et ne récupère l'audience que par les scopes qu'il a demandés. Les trois
copies doivent donc porter la **même** valeur `included.custom.audience` ; le
harness les réécrit toutes d'un coup, en refusant de démarrer s'il n'en trouve
aucune.

### Client scopes intégrés

`clientScopes` contient aussi les scopes standards de Keycloak (`acr`, `basic`,
`email`, `profile`, `roles`, `web-origins`, `address`, `microprofile-jwt`,
`phone`). Ce n'est pas de la redondance : **dès qu'un export fournit
`clientScopes`, Keycloak ne crée plus les scopes par défaut**. Les omettre casse
chaque référence à un scope standard dans `defaultClientScopes` /
`optionalClientScopes`. `defaultDefaultClientScopes` et
`defaultOptionalClientScopes` fixent ce que reçoit tout nouveau client — y
compris ceux créés par DCR.

**`offline_access` en est délibérément absent.** Keycloak ne se contente pas de
créer ce scope : `setupOfflineTokens` crée *aussi* le rôle realm
`offline_access` et l'ajoute au rôle composite par défaut — et il ne le fait que
si le scope n'existe pas encore. Le déclarer dans l'export fait sauter cette
initialisation : le scope existe, le rôle non, et toute demande d'offline token
échoue en `not_allowed: Offline tokens not allowed for the user or client`.
Cela se voit tout de suite avec rmcp, qui ajoute `offline_access` à sa demande
dès que l'AS l'annonce dans `scopes_supported` (SEP-2207) — et Keycloak
l'annonce toujours, puisqu'il liste tous les client scopes du realm. En
laissant Keycloak s'en charger, l'enregistrement dynamique et le flux
d'autorisation passent tous les deux ; `mcp-client` le garde explicitement dans
ses `optionalClientScopes`, sans quoi Keycloak refuse (`invalid_scope`) la
demande que rmcp construit.

### Politiques d'enregistrement dynamique (DCR)

`components` porte les *Client Registration Policies* sous
`org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy`, en
deux sous-types (`anonymous` et `authenticated`) :

| Politique | Rôle |
|---|---|
| `trusted-hosts` | valide les `redirect_uri` demandés contre la liste d'hôtes (la vérification de l'IP émettrice, elle, est désactivée — voir plus bas) |
| `allowed-client-templates` | limite les client scopes qu'un client enregistré peut réclamer |
| `allowed-protocol-mappers` | liste blanche de mappers — empêche un client enregistré de se fabriquer des claims |
| `max-clients` | plafond de clients (200) |
| `consent-required` | force le consentement pour les clients anonymes |

`allowed-client-templates` (affiché « Allowed Client Scopes ») porte
`allowed-client-scopes: ["openid"]` en plus de `allow-default-scopes: true`.
La politique valide chaque nom présent dans le `scope` de la demande RFC 7591
contre les client scopes du realm — et `openid` n'en est pas un. Sans cette
entrée, toute demande d'enregistrement contenant `openid` (c'est-à-dire toute
demande d'un client OIDC normal, rmcp compris) est refusée en `403
insufficient_scope`.

**Où atterrit l'enregistrement.** En mode resource server, un client conforme à
la RFC 9728 lit la métadonnée de ressource protégée du framework, suit
`authorization_servers` jusqu'à Keycloak, et s'enregistre **directement** au
`registration_endpoint` de Keycloak : il ne passe pas par `/oauth/register`. Ce
sont donc bien les politiques `anonymous` ci-dessus qui décident. Le proxy
`/oauth/register` reste néanmoins servi, et reste nécessaire, pour les clients
navigateur et les clients MCP 2025-03-26 qui interrogent le serveur de ressource
lui-même : le endpoint `clients-registrations/openid-connect` de Keycloak ne
renvoie aucun en-tête CORS.

> **Piège Keycloak : un `scope` dans la demande RFC 7591 remplace les default
> client scopes.** Un enregistrement *sans* `scope` donne au client les default
> client scopes du realm (`mcp-audience` compris). Un enregistrement *avec*
> `scope` — ce que fait rmcp — ne lui laisse que `basic` en default, tout le
> reste passant en optionnel. Le client obtenu n'a donc plus `mcp-audience`, ses
> tokens n'ont plus d'`aud`, et le serveur MCP les refuse en `401`. C'est la
> raison pour laquelle le mapper d'audience est *aussi* posé sur `mcp:tools` et
> `mcp:resources` : ces scopes-là, le client les a demandés, donc il les garde.

**Les deux moitiés de `trusted-hosts` ne se valent pas.**
`client-uris-must-match: true` valide les `redirect_uri` (et autres URI) que la
demande d'enregistrement réclame : c'est la moitié qui protège réellement,
puisqu'un client enregistré avec un `redirect_uri` arbitraire est un vol de code
d'autorisation en attente. `host-sending-registration-request-must-match`, en
revanche, compare l'**adresse IP source** de la requête d'enregistrement à la
liste d'hôtes — et en mode resource server c'est le client MCP lui-même qui
s'enregistre, depuis n'importe où sur Internet, puisque c'est là que la
métadonnée de ressource protégée l'envoie. Cette moitié refuse donc
systématiquement, y compris le client parfaitement légitime. Le realm livre
`host-sending-registration-request-must-match: false` et
`client-uris-must-match: true`.

Un déploiement qui n'accepte l'enregistrement dynamique que depuis son propre
réseau peut la réactiver : elle redevient sensée quand l'émetteur de la demande
est une machine connue. Ce n'est pas le cas d'un client MCP.

> **À confirmer.** `trusted-hosts` liste `mcp.example.com`, `localhost` et
> `127.0.0.1`. À aligner sur le nom d'hôte public réel avant mise en production
> — c'est cette liste qui décide des `redirect_uri` acceptables, donc la laisser
> sur les valeurs d'exemple revient à n'autoriser que des clients loopback.

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

### Utilisateurs

Aucun. Un fichier importable qui embarque des comptes activés avec des mots de
passe permanents et devinables est un piège tendu à qui l'importe dans un vrai
Keycloak. Le harness injecte `alice` / `alice` et `bob` / `bob` dans sa copie
éphémère — deux principals distincts, ce qu'il lui faut pour vérifier
l'isolation des identités de session.

### `sslRequired: "external"`

Le défaut Keycloak, et le bon réglage pour un realm réel. Le harness le ramène à
`"none"` dans sa copie : le conteneur ne parle que HTTP.

## Configuration correspondante du serveur MCP

```bash
MCP_TOKEN_MODE=resource_server
OAUTH_UNKNOWN_TOKEN_VALIDATION=jwks
OAUTH_EXPECTED_AUDIENCE=https://mcp.example.com/mcp   # = valeur du mapper d'audience
OAUTH_ISSUER_URL=https://<keycloak>/realms/mcp
OAUTH_CLIENT_ID=mcp-client
OAUTH_SCOPES=openid,profile,email,mcp:tools,mcp:resources
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
