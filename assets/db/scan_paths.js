// assets/db/scan_paths.js — PenTri v1.10
// 민감 경로 탐지 DB — 카테고리별 분류
const SCAN_PATHS = {

  admin: {
    label: '관리 콘솔',
    icon:  '🔐',
    paths: [
      '/admin', '/admin/', '/admin/login', '/admin/dashboard',
      '/administrator', '/administrator/',
      '/manager', '/manager/',
      '/management', '/console',
      '/dashboard', '/dashboard/',
      '/wp-admin', '/wp-admin/',
      '/wp-login.php',
      '/phpmyadmin', '/phpmyadmin/',
      '/pma', '/pma/',
      '/cpanel', '/webmail',
      '/plesk', '/directadmin',
      '/panel', '/control',
      '/superadmin', '/siteadmin',
      '/moderator', '/webmaster',
    ]
  },

  devtools: {
    label: '개발 도구 / API 문서',
    icon:  '🛠️',
    paths: [
      '/actuator', '/actuator/',
      '/actuator/health', '/actuator/info',
      '/actuator/env', '/actuator/beans',
      '/actuator/mappings', '/actuator/metrics',
      '/actuator/loggers', '/actuator/threaddump',
      '/actuator/heapdump',
      '/swagger-ui', '/swagger-ui/',
      '/swagger-ui.html', '/swagger-ui/index.html',
      '/swagger', '/swagger/',
      '/api-docs', '/api-docs/',
      '/v2/api-docs', '/v3/api-docs',
      '/openapi', '/openapi.json', '/openapi.yaml',
      '/graphql', '/graphiql', '/graphql/console',
      '/redoc', '/docs', '/docs/',
      '/api/swagger', '/api/docs',
      '/api/v1', '/api/v2', '/api/v3',
      '/__debug__', '/debug', '/debug/',
      '/rails/info', '/rails/mailers',
      '/django-admin', '/_profiler',
      '/telescope', '/horizon',
    ]
  },

  config: {
    label: '설정 파일',
    icon:  '⚙️',
    paths: [
      '/.env', '/.env.local', '/.env.dev',
      '/.env.development', '/.env.production',
      '/.env.staging', '/.env.test',
      '/config.php', '/config.yml', '/config.yaml',
      '/config.json', '/config.xml',
      '/configuration.php', '/configuration.yml',
      '/settings.php', '/settings.py',
      '/web.config', '/app.config',
      '/application.properties', '/application.yml',
      '/database.yml', '/database.php',
      '/wp-config.php', '/wp-config.php.bak',
      '/composer.json', '/package.json',
      '/Gemfile', '/requirements.txt',
      '/dockerfile', '/docker-compose.yml',
      '/Makefile', '/.htaccess', '/.htpasswd',
      '/nginx.conf', '/apache.conf',
    ]
  },

  backup: {
    label: '백업 / 임시 파일',
    icon:  '💾',
    paths: [
      '/backup', '/backup/',
      '/backup.sql', '/backup.zip', '/backup.tar.gz',
      '/backup.bak', '/backup.old',
      '/db.sql', '/database.sql', '/dump.sql',
      '/data.sql', '/mysql.sql',
      '/site.zip', '/site.tar.gz', '/www.zip',
      '/files.zip', '/upload.zip',
      '/old', '/old/',
      '/temp', '/tmp', '/cache',
      '/.DS_Store', '/Thumbs.db',
      '/log', '/logs', '/log/',
      '/error.log', '/access.log', '/debug.log',
      '/test', '/test/', '/testing',
      '/dev', '/development',
      '/staging',
    ]
  },

  vcs: {
    label: 'VCS / 소스코드',
    icon:  '📦',
    paths: [
      '/.git', '/.git/',
      '/.git/HEAD', '/.git/config',
      '/.git/COMMIT_EDITMSG',
      '/.git/index', '/.git/packed-refs',
      '/.gitignore', '/.gitmodules',
      '/.svn', '/.svn/entries',
      '/.svn/wc.db',
      '/.hg', '/.hg/hgrc',
      '/.bzr', '/.bzr/branch-format',
      '/CVS', '/CVS/Root',
      '/.github', '/.github/',
      '/.gitlab-ci.yml',
      '/bitbucket-pipelines.yml',
    ]
  },

  auth: {
    label: '인증 / 세션',
    icon:  '🔑',
    paths: [
      '/login', '/login/',
      '/logout', '/logout/',
      '/register', '/signup', '/signup/',
      '/forgot-password', '/reset-password',
      '/oauth', '/oauth2', '/oauth/authorize',
      '/auth', '/auth/',
      '/sso', '/saml', '/saml2',
      '/token', '/refresh-token',
      '/api/login', '/api/auth', '/api/token',
      '/user', '/users', '/users/',
      '/profile', '/account', '/account/',
      '/me', '/api/me', '/api/user',
    ]
  },

  upload: {
    label: '업로드 / 파일',
    icon:  '📤',
    paths: [
      '/upload', '/upload/',
      '/uploads', '/uploads/',
      '/files', '/files/',
      '/file', '/file/',
      '/media', '/media/',
      '/static', '/static/',
      '/assets', '/assets/',
      '/images', '/images/',
      '/img', '/img/',
      '/download', '/download/',
      '/downloads', '/downloads/',
      '/export', '/export/',
      '/import', '/import/',
      '/attachments', '/attachments/',
    ]
  },

};
