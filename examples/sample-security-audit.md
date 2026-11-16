# Auditoría de secretos — leaky-app

_Fecha: 2026-11-16 · Modo: repositorio_

**Veredicto:** hay 12 problema(s) crítico(s) o alto(s) confirmados. Empieza por rotar las claves de la lista de abajo.

Confirmados: **14** · Por validar: **1** · Descartados: **1**

## Claves que debes rotar

Rótalas en el panel de cada proveedor **antes** de limpiar el código o el historial.

- [ ] Anthropic API key · `sk-ant…_l (107 chars)` · `.env`
- [ ] Secreto con prefijo público: NEXT_PUBLIC_OPENAI_API_KEY · `sk-pro…I9 (72 chars)` · `.env.local`
- [ ] GitHub token · `ghp_iQ…bL (40 chars)` · `.mcp.json`
- [ ] Stripe live secret/restricted key · `sk_liv…Xi (40 chars)` · `Dockerfile`, `app/api/checkout/route.ts`
- [ ] Anthropic API key · `sk-ant…_l (106 chars)` · `app/components/Chat.tsx`
- [ ] URL de base de datos con contraseña · `h4gVJj…Fq (20 chars)` · `docker-compose.yml`
- [ ] Supabase service_role key · `eyJhbG…ty (209 chars)` · `lib/supabase.ts`

## Hallazgos confirmados

| Severidad | Qué | Dónde | Exposición |
|---|---|---|---|
| 🔴 critical | Anthropic API key en el historial de git | `.env` | en el repositorio git |
| 🔴 critical | Archivo .env.local versionado | `.env.local` | en el repositorio git |
| 🔴 critical | Secreto con prefijo público: NEXT_PUBLIC_OPENAI_API_KEY | `.env.local`:1 | público (cualquiera puede verlo) |
| 🔴 critical | GitHub token | `.mcp.json`:10 | en el repositorio git |
| 🔴 critical | Stripe live secret/restricted key | `Dockerfile`:5 | en el repositorio git |
| 🔴 critical | Stripe live secret/restricted key | `app/api/checkout/route.ts`:2 | en el repositorio git |
| 🔴 critical | Anthropic API key | `app/components/Chat.tsx`:5 | público (cualquiera puede verlo) |
| 🔴 critical | URL de base de datos con contraseña | `docker-compose.yml`:9 | en el repositorio git |
| 🔴 critical | Supabase service_role key | `lib/supabase.ts`:3 | en el repositorio git |
| 🟠 high | El Dockerfile copia un .env dentro de la imagen | `Dockerfile`:4 | — |
| 🟠 high | El código usa NEXT_PUBLIC_OPENAI_API_KEY (sensible y público) | `app/components/Chat.tsx`:8 | público (cualquiera puede verlo) |
| 🟠 high | Reglas de Firebase abiertas | `firestore.rules` | — |
| 🟡 medium | .env no está en .gitignore | `.gitignore` | — |
| ⚪ info | Hay Dockerfile pero no .dockerignore | `Dockerfile` | — |

### 🔴 Anthropic API key en el historial de git
- **Dónde:** `.env` · `sk-ant…_l (107 chars)`
- **Por qué importa:** Introducido en el commit 167eac3 2026-11-15. Ya no está en el código actual, pero cualquiera con acceso al repo puede recuperarlo.
- **Cómo se ha comprobado:** Introducida en el commit "initial setup" y borrada en el siguiente; el commit es alcanzable desde main, así que cualquiera con acceso al repo puede recuperarla.
- **Cómo arreglarlo:** Aunque ya no esté en el código, sigue en el historial de git. Rótala primero; después, si el repo es o será público, limpia el historial con git filter-repo o BFG.

### 🔴 Archivo .env.local versionado
- **Dónde:** `.env.local`
- **Por qué importa:** Contiene 2 valores reales.
- **Cómo se ha comprobado:** `git ls-files` incluye .env.local; .gitignore no tiene reglas para .env*.
- **Cómo arreglarlo:** Saca el archivo del repositorio (git rm --cached), añade '.env*' (excepto .env.example) a .gitignore y rota todos los valores que contenía.

### 🔴 Secreto con prefijo público: NEXT_PUBLIC_OPENAI_API_KEY
- **Dónde:** `.env.local`:1 · `sk-pro…I9 (72 chars)`
- **Por qué importa:** Las variables con prefijos como NEXT_PUBLIC_, VITE_ o PUBLIC_ se incrustan en el JavaScript que descarga el navegador.
- **Cómo se ha comprobado:** NEXT_PUBLIC_OPENAI_API_KEY se lee en app/components/Chat.tsx, que es "use client": Next.js incrusta el valor en el bundle del navegador.
- **Cómo arreglarlo:** Esta clave llega al navegador: cualquiera puede leerla. Rótala y mueve la llamada a un endpoint de servidor (API route / server action / edge function) que use la clave sin exponerla.

### 🔴 GitHub token
- **Dónde:** `.mcp.json`:10 · `ghp_iQ…bL (40 chars)`
- **Por qué importa:** Configuración de servidor MCP versionada con el token en claro.
- **Cómo se ha comprobado:** .mcp.json está versionado y el token aparece en claro en env.GITHUB_PERSONAL_ACCESS_TOKEN.
- **Cómo arreglarlo:** Los tokens de servidores MCP no deben ir en archivos versionados: usa variables de entorno ("env": {"TOKEN": "${TOKEN}"}) o un archivo local ignorado, y rota el token.

### 🔴 Stripe live secret/restricted key
- **Dónde:** `Dockerfile`:5 · `sk_liv…Xi (40 chars)`
- **Cómo se ha comprobado:** Clave sk_live en claro; en el Dockerfile además queda en una capa ENV de la imagen.
- **Cómo arreglarlo:** Rota la clave en el panel del proveedor (asúmela comprometida), muévela a una variable de entorno de servidor y elimina el valor del código.

### 🔴 Stripe live secret/restricted key
- **Dónde:** `app/api/checkout/route.ts`:2 · `sk_liv…Xi (40 chars)`
- **Cómo se ha comprobado:** Clave sk_live en claro; en el Dockerfile además queda en una capa ENV de la imagen.
- **Cómo arreglarlo:** Rota la clave en el panel del proveedor (asúmela comprometida), muévela a una variable de entorno de servidor y elimina el valor del código.

### 🔴 Anthropic API key
- **Dónde:** `app/components/Chat.tsx`:5 · `sk-ant…_l (106 chars)`
- **Por qué importa:** El archivo parece ejecutarse en el navegador, así que la clave es pública.
- **Cómo se ha comprobado:** Chat.tsx empieza con "use client" e instancia el SDK con dangerouslyAllowBrowser: true; la clave viaja al navegador.
- **Cómo arreglarlo:** Esta clave llega al navegador: cualquiera puede leerla. Rótala y mueve la llamada a un endpoint de servidor (API route / server action / edge function) que use la clave sin exponerla.

### 🔴 URL de base de datos con contraseña
- **Dónde:** `docker-compose.yml`:9 · `h4gVJj…Fq (20 chars)`
- **Por qué importa:** Con esta URL cualquiera puede conectarse a la base de datos si el puerto es accesible.
- **Cómo se ha comprobado:** docker-compose.yml está versionado con la contraseña de Postgres en claro, repetida en POSTGRES_PASSWORD.
- **Cómo arreglarlo:** Rota la clave en el panel del proveedor (asúmela comprometida), muévela a una variable de entorno de servidor y elimina el valor del código.

### 🔴 Supabase service_role key
- **Dónde:** `lib/supabase.ts`:3 · `eyJhbG…ty (209 chars)`
- **Por qué importa:** La service_role ignora todas las políticas RLS: quien la tenga puede leer y escribir toda la base de datos.
- **Cómo se ha comprobado:** El JWT decodificado tiene role=service_role; lib/supabase.ts no está bajo una ruta de servidor y lo importa código compartido.
- **Cómo arreglarlo:** Rota la clave en el panel del proveedor (asúmela comprometida), muévela a una variable de entorno de servidor y elimina el valor del código.

### 🟠 El Dockerfile copia un .env dentro de la imagen
- **Dónde:** `Dockerfile`:4
- **Cómo se ha comprobado:** COPY .env .env en la línea 4: el .env queda dentro de la imagen aunque no esté en el repo.
- **Cómo arreglarlo:** No copies .env a la imagen; añade '.env*' a .dockerignore y pasa las variables en runtime.

### 🟠 El código usa NEXT_PUBLIC_OPENAI_API_KEY (sensible y público)
- **Dónde:** `app/components/Chat.tsx`:8
- **Por qué importa:** El nombre indica una credencial privada, pero el prefijo la expone al cliente.
- **Cómo se ha comprobado:** process.env.NEXT_PUBLIC_OPENAI_API_KEY en un componente cliente.
- **Cómo arreglarlo:** Esta clave llega al navegador: cualquiera puede leerla. Rótala y mueve la llamada a un endpoint de servidor (API route / server action / edge function) que use la clave sin exponerla.

### 🟠 Reglas de Firebase abiertas
- **Dónde:** `firestore.rules`
- **Por qué importa:** Cualquiera con la config pública del proyecto puede leer o escribir datos.
- **Cómo se ha comprobado:** match /{document=**} con allow read, write: if true; cualquiera puede leer y escribir toda la base de datos.
- **Cómo arreglarlo:** Restringe por request.auth y por propietario del documento; prueba las reglas con el emulador.

### 🟡 .env no está en .gitignore
- **Dónde:** `.gitignore`
- **Cómo se ha comprobado:** git check-ignore .env no devuelve ninguna regla.
- **Cómo arreglarlo:** Añade a .gitignore: `.env`, `.env.*` y `!.env.example`.

### ⚪ Hay Dockerfile pero no .dockerignore · refuerzo
- **Dónde:** `Dockerfile`
- **Cómo se ha comprobado:** Sin .dockerignore, COPY . . mete node_modules y archivos locales en la imagen; el .env ya está cubierto por otro hallazgo.
- **Cómo arreglarlo:** Crea .dockerignore con al menos: .env*, .git, node_modules.

## Por validar

Sin severidad hasta resolver la duda concreta de cada uno.

- **AWS access key ID** (`CLAUDE.md`): El ID de acceso aparece en CLAUDE.md, pero no hay ninguna AWS secret key en el repo ni en el historial: ¿sigue activa y dónde está su secreto?

<details><summary>Descartados (1)</summary>

- Source map publicado (`public/_next/static/chunks/main.js.map`): public/_next/static es salida de build local y el despliegue la regenera sin source maps (productionBrowserSourceMaps no está activado).

</details>

---
_Generado con [Forja Secrets Audit](https://github.com/ivanqv/Forja-Secrets-Audit). Los valores están redactados; nunca se muestran secretos completos._