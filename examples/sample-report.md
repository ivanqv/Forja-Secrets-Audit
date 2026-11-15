# Forja Secrets Audit — leaky-app

- Repositorio git: sí · Historial analizado: sí
- Resumen: 🔴 critical: 8 · 🟠 high: 5 · 🟡 medium: 2 · 🔵 low: 1

## 🔴 CRITICAL (8)

### Anthropic API key en el historial de git
- **Dónde:** `.env` · **Valor:** `sk-ant…_l (107 chars)`
- **Por qué importa:** Introducido en el commit <hash> 2026-11-15. Ya no está en el código actual, pero cualquiera con acceso al repo puede recuperarlo.
- **Cómo arreglarlo:** Aunque ya no esté en el código, sigue en el historial de git. Rótala primero; después, si el repo es o será público, limpia el historial con git filter-repo o BFG.

### Archivo .env.local versionado
- **Dónde:** `.env.local`
- **Por qué importa:** Contiene 2 valores reales.
- **Cómo arreglarlo:** Saca el archivo del repositorio (git rm --cached), añade '.env*' (excepto .env.example) a .gitignore y rota todos los valores que contenía.

### Secreto con prefijo público: NEXT_PUBLIC_OPENAI_API_KEY
- **Dónde:** `.env.local`:1 · **Valor:** `sk-pro…I9 (72 chars)`
- **Por qué importa:** Las variables con prefijos como NEXT_PUBLIC_, VITE_ o PUBLIC_ se incrustan en el JavaScript que descarga el navegador.
- **Cómo arreglarlo:** Esta clave llega al navegador: cualquiera puede leerla. Rótala y mueve la llamada a un endpoint de servidor (API route / server action / edge function) que use la clave sin exponerla.

### GitHub token
- **Dónde:** `.mcp.json`:10 · **Valor:** `ghp_iQ…bL (40 chars)`
- **Por qué importa:** Configuración de servidor MCP versionada con el token en claro.
- **Cómo arreglarlo:** Los tokens de servidores MCP no deben ir en archivos versionados: usa variables de entorno ("env": {"TOKEN": "${TOKEN}"}) o un archivo local ignorado, y rota el token.

### Stripe live secret/restricted key
- **Dónde:** `Dockerfile`:5 · **Valor:** `sk_liv…Xi (40 chars)`
- **Cómo arreglarlo:** Rota la clave en el panel del proveedor (asúmela comprometida), muévela a una variable de entorno de servidor y elimina el valor del código.

### Stripe live secret/restricted key
- **Dónde:** `app/api/checkout/route.ts`:2 · **Valor:** `sk_liv…Xi (40 chars)`
- **Cómo arreglarlo:** Rota la clave en el panel del proveedor (asúmela comprometida), muévela a una variable de entorno de servidor y elimina el valor del código.

### Anthropic API key
- **Dónde:** `app/components/Chat.tsx`:5 · **Valor:** `sk-ant…_l (106 chars)`
- **Por qué importa:** El archivo parece ejecutarse en el navegador, así que la clave es pública.
- **Cómo arreglarlo:** Esta clave llega al navegador: cualquiera puede leerla. Rótala y mueve la llamada a un endpoint de servidor (API route / server action / edge function) que use la clave sin exponerla.

### Supabase service_role key
- **Dónde:** `lib/supabase.ts`:3 · **Valor:** `eyJhbG…ty (209 chars)`
- **Por qué importa:** La service_role ignora todas las políticas RLS: quien la tenga puede leer y escribir toda la base de datos.
- **Cómo arreglarlo:** Rota la clave en el panel del proveedor (asúmela comprometida), muévela a una variable de entorno de servidor y elimina el valor del código.

## 🟠 HIGH (5)

### AWS access key ID
- **Dónde:** `CLAUDE.md`:3 · **Valor:** `AKIA9O…5N (20 chars)`
- **Por qué importa:** Credencial escrita en un archivo de contexto para asistentes de IA.
- **Cómo arreglarlo:** Los archivos de contexto de IA (CLAUDE.md, .cursorrules…) se versionan y se envían al modelo: no pongas credenciales ahí. Rótala y referencia la variable de entorno por su nombre.

### El Dockerfile copia un .env dentro de la imagen
- **Dónde:** `Dockerfile`:4
- **Cómo arreglarlo:** No copies .env a la imagen; añade '.env*' a .dockerignore y pasa las variables en runtime.

### El código usa NEXT_PUBLIC_OPENAI_API_KEY (sensible y público)
- **Dónde:** `app/components/Chat.tsx`:8
- **Por qué importa:** El nombre indica una credencial privada, pero el prefijo la expone al cliente.
- **Cómo arreglarlo:** Esta clave llega al navegador: cualquiera puede leerla. Rótala y mueve la llamada a un endpoint de servidor (API route / server action / edge function) que use la clave sin exponerla.

### URL de base de datos con contraseña
- **Dónde:** `docker-compose.yml`:9 · **Valor:** `h4gVJj…Fq (20 chars)`
- **Por qué importa:** Con esta URL cualquiera puede conectarse a la base de datos si el puerto es accesible.
- **Cómo arreglarlo:** Rota la clave en el panel del proveedor (asúmela comprometida), muévela a una variable de entorno de servidor y elimina el valor del código.

### Reglas de Firebase abiertas
- **Dónde:** `firestore.rules`
- **Por qué importa:** Cualquiera con la config pública del proyecto puede leer o escribir datos.
- **Cómo arreglarlo:** Restringe por request.auth y por propietario del documento; prueba las reglas con el emulador.

## 🟡 MEDIUM (2)

### .env no está en .gitignore
- **Dónde:** `.gitignore`
- **Cómo arreglarlo:** Añade a .gitignore: `.env`, `.env.*` y `!.env.example`.

### Source map publicado
- **Dónde:** `public/_next/static/chunks/main.js.map`
- **Por qué importa:** Los source maps en carpetas públicas permiten reconstruir tu código fuente original, incluidos comentarios y rutas internas.
- **Cómo arreglarlo:** Desactiva los source maps en producción (p. ej. productionBrowserSourceMaps: false, build.sourcemap: false) o súbelos solo a tu herramienta de errores.

## 🔵 LOW (1)

### Hay Dockerfile pero no .dockerignore
- **Dónde:** `Dockerfile`
- **Cómo arreglarlo:** Crea .dockerignore con al menos: .env*, .git, node_modules.
