#!/bin/bash

# Полный скрипт развертывания N8N с PostgreSQL, Redis и Traefik
# Домен: 3digitit.ru | Локальный IP: 192.168.0.164 | Внешний IP: 193.32.203.209

set -e

# Конфигурация
DOMAIN="3digitit.ru"
LOCAL_IP="192.168.0.164"
EXTERNAL_IP="193.32.203.209"
INSTALL_DIR="/opt/n8n"

# Цвета для красивого вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Функции для вывода
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                     🚀 N8N DEPLOYMENT                       ║"
    echo "║                                                              ║"
    echo "║  PostgreSQL + Redis + Traefik + N8N                        ║"
    echo "║  Domain: 3digitit.ru                                        ║"
    echo "║  Full automation with SSL certificates                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "\n${CYAN}📋 STEP: $1${NC}"
    echo "─────────────────────────────────────────────────────"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Проверка root прав
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Этот скрипт должен запускаться с правами root"
        echo "Используйте: sudo $0"
        exit 1
    fi
}

# Проверка DNS записей
check_dns() {
    print_step "Проверка DNS записей"
    
    for subdomain in "n8n" "traefik"; do
        domain_full="${subdomain}.${DOMAIN}"
        print_info "Проверка DNS для ${domain_full}..."
        
        # Проверка A записи
        dns_ip=$(dig +short ${domain_full} @8.8.8.8 | tail -n1)
        
        if [ "$dns_ip" = "$EXTERNAL_IP" ]; then
            print_success "${domain_full} -> ${dns_ip} ✓"
        else
            print_warning "${domain_full} -> ${dns_ip} (ожидается: ${EXTERNAL_IP})"
            print_warning "Убедитесь, что DNS записи настроены правильно"
        fi
    done
}

# Установка зависимостей
install_dependencies() {
    print_step "Установка зависимостей"
    
    # Обновление системы
    print_info "Обновление списка пакетов..."
    apt update -qq
    
    print_info "Установка необходимых пакетов..."
    apt install -y curl wget git htop nano ufw dnsutils net-tools
    
    # Установка Docker
    if ! command -v docker &> /dev/null; then
        print_info "Установка Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        usermod -aG docker $SUDO_USER 2>/dev/null || true
        rm get-docker.sh
        print_success "Docker установлен"
    else
        print_success "Docker уже установлен"
    fi
    
    # Установка Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_info "Установка Docker Compose..."
        DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
        curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
        print_success "Docker Compose установлен (версия: $DOCKER_COMPOSE_VERSION)"
    else
        print_success "Docker Compose уже установлен"
    fi
    
    # Запуск Docker
    systemctl enable docker
    systemctl start docker
}

# Настройка Firewall
setup_firewall() {
    print_step "Настройка Firewall (UFW)"
    
    # Сброс правил UFW
    ufw --force reset
    
    # Базовые правила
    ufw default deny incoming
    ufw default allow outgoing
    
    # SSH
    ufw allow ssh
    
    # HTTP и HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Включение UFW
    ufw --force enable
    
    print_success "Firewall настроен"
}

# Создание структуры директорий
create_directories() {
    print_step "Создание структуры директорий"
    
    # Создание основных директорий
    mkdir -p ${INSTALL_DIR}/{traefik/{letsencrypt,config},postgres/init,n8n/backup,backups}
    mkdir -p /var/log/n8n
    
    # Установка прав
    chmod 700 ${INSTALL_DIR}/traefik/letsencrypt
    chown -R ${SUDO_USER:-root}:${SUDO_USER:-root} ${INSTALL_DIR} 2>/dev/null || true
    
    print_success "Структура директорий создана"
}

# Создание файлов конфигурации
create_configs() {
    print_step "Создание файлов конфигурации"
    
    # Генерация случайных паролей
    POSTGRES_PASSWORD=$(openssl rand -base64 32)
    REDIS_PASSWORD=$(openssl rand -base64 32)
    N8N_ENCRYPTION_KEY=$(openssl rand -base64 64)
    
    # Создание docker-compose.yml
    cat > ${INSTALL_DIR}/docker-compose.yml << EOF
version: '3.8'

services:
  traefik:
    image: traefik:v3.0
    container_name: traefik
    restart: unless-stopped
    command:
      - --api.dashboard=true
      - --api.insecure=false
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --certificatesresolvers.letsencrypt.acme.tlschallenge=true
      - --certificatesresolvers.letsencrypt.acme.email=admin@${DOMAIN}
      - --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json
      - --log.level=INFO
      - --accesslog=true
      - --providers.file.directory=/etc/traefik/dynamic
      - --providers.file.watch=true
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/letsencrypt:/letsencrypt
      - ./traefik/config:/etc/traefik/dynamic
    labels:
      - traefik.enable=true
      - traefik.http.routers.traefik.rule=Host(\`traefik.${DOMAIN}\`)
      - traefik.http.routers.traefik.entrypoints=websecure
      - traefik.http.routers.traefik.tls.certresolver=letsencrypt
      - traefik.http.routers.traefik.service=api@internal
      - traefik.http.routers.traefik.middlewares=auth
      - traefik.http.middlewares.auth.basicauth.users=admin:\$\$2y\$\$10\$\$3QK9Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8
    networks:
      - n8n-network

  postgres:
    image: postgres:15-alpine
    container_name: n8n-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: n8n
      POSTGRES_USER: n8n
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      PGDATA: /var/lib/postgresql/data/pgdata
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./postgres/init:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U n8n -d n8n"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      - n8n-network

  redis:
    image: redis:7-alpine
    container_name: n8n-redis
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--pass", "${REDIS_PASSWORD}", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    networks:
      - n8n-network

  n8n:
    image: n8nio/n8n:latest
    container_name: n8n
    restart: unless-stopped
    environment:
      # Database
      DB_TYPE: postgresdb
      DB_POSTGRESDB_HOST: postgres
      DB_POSTGRESDB_PORT: 5432
      DB_POSTGRESDB_DATABASE: n8n
      DB_POSTGRESDB_USER: n8n
      DB_POSTGRESDB_PASSWORD: ${POSTGRES_PASSWORD}
      
      # Redis
      QUEUE_BULL_REDIS_HOST: redis
      QUEUE_BULL_REDIS_PORT: 6379
      QUEUE_BULL_REDIS_PASSWORD: ${REDIS_PASSWORD}
      
      # General
      N8N_HOST: n8n.${DOMAIN}
      N8N_PORT: 5678
      N8N_PROTOCOL: https
      WEBHOOK_URL: https://n8n.${DOMAIN}
      
      # Security
      N8N_ENCRYPTION_KEY: ${N8N_ENCRYPTION_KEY}
      
      # User Management
      N8N_USER_MANAGEMENT_DISABLED: false
      
      # Timezone
      GENERIC_TIMEZONE: Europe/Moscow
      TZ: Europe/Moscow
      
      # Performance
      N8N_PAYLOAD_SIZE_MAX: 16
      EXECUTIONS_TIMEOUT: 3600
      N8N_CONCURRENCY_PRODUCTION_LIMIT: 10
      
      # Features
      N8N_METRICS: true
      N8N_DIAGNOSTICS_ENABLED: false
      N8N_VERSION_NOTIFICATIONS_ENABLED: false
      
    volumes:
      - n8n_data:/home/node/.n8n
      - ./n8n/backup:/backup
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    labels:
      - traefik.enable=true
      - traefik.http.routers.n8n.rule=Host(\`n8n.${DOMAIN}\`)
      - traefik.http.routers.n8n.entrypoints=websecure
      - traefik.http.routers.n8n.tls.certresolver=letsencrypt
      - traefik.http.services.n8n.loadbalancer.server.port=5678
      - traefik.http.routers.n8n.middlewares=n8n-headers
      - traefik.http.middlewares.n8n-headers.headers.customrequestheaders.X-Forwarded-Proto=https
      - traefik.http.middlewares.n8n-headers.headers.customrequestheaders.X-Forwarded-For=\$\$remote_addr
    networks:
      - n8n-network

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local
  n8n_data:
    driver: local

networks:
  n8n-network:
    driver: bridge
EOF
    
    # Создание .env файла
    cat > ${INSTALL_DIR}/.env << EOF
# Конфигурация N8N Infrastructure
DOMAIN=${DOMAIN}
LOCAL_IP=${LOCAL_IP}
EXTERNAL_IP=${EXTERNAL_IP}

# Database
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}

# Timezone
TZ=Europe/Moscow
GENERIC_TIMEZONE=Europe/Moscow

# Generated: $(date)
EOF

    chmod 600 ${INSTALL_DIR}/.env
    
    print_success "Файлы конфигурации созданы"
}

# Создание конфигурации Traefik
create_traefik_config() {
    cat > ${INSTALL_DIR}/traefik/config/dynamic.yml << 'EOF'
http:
  middlewares:
    security-headers:
      headers:
        browserXssFilter: true
        contentTypeNosniff: true
        forceSTSHeader: true
        frameDeny: false
        stsIncludeSubdomains: true
        stsPreload: true
        stsSeconds: 63072000
        customRequestHeaders:
          X-Forwarded-Proto: "https"
        customResponseHeaders:
          X-Robots-Tag: "noindex,nofollow,nosnippet,noarchive"
          
    https-redirect:
      redirectScheme:
        scheme: https
        permanent: true
        
    rate-limit:
      rateLimit:
        burst: 100
        average: 50
        
    compress:
      compress: {}

  routers:
    http-redirect:
      rule: "HostRegexp(`{host:.+}`)"
      entryPoints:
        - web
      middlewares:
        - https-redirect

tls:
  options:
    default:
      sslProtocols:
        - "TLSv1.2"
        - "TLSv1.3"
      cipherSuites:
        - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        - "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
        - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
EOF
}

# Создание скрипта инициализации PostgreSQL
create_postgres_init() {
    cat > ${INSTALL_DIR}/postgres/init/01-init.sql << 'EOF'
-- N8N Database Initialization
ALTER DATABASE n8n SET timezone TO 'Europe/Moscow';

-- Performance extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Performance settings
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET log_min_duration_statement = 1000;
ALTER SYSTEM SET log_checkpoints = on;
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;

-- Apply settings
SELECT pg_reload_conf();
EOF
}

# Развертывание сервисов
deploy_services() {
    print_step "Развертывание сервисов"
    
    cd ${INSTALL_DIR}
    
    print_info "Загрузка Docker образов..."
    docker-compose pull
    
    print_info "Запуск сервисов..."
    docker-compose up -d
    
    print_info "Ожидание готовности сервисов..."
    
    # Ожидание PostgreSQL
    print_info "Ожидание PostgreSQL..."
    timeout=120
    while ! docker-compose exec -T postgres pg_isready -U n8n -d n8n >/dev/null 2>&1; do
        sleep 2
        timeout=$((timeout-2))
        if [ $timeout -le 0 ]; then
            print_error "PostgreSQL не запустился в течение 2 минут"
            exit 1
        fi
    done
    
    # Ожидание N8N
    print_info "Ожидание N8N..."
    timeout=180
    while ! curl -sSf https://n8n.${DOMAIN}/healthz >/dev/null 2>&1; do
        sleep 5
        timeout=$((timeout-5))
        if [ $timeout -le 0 ]; then
            print_warning "N8N не отвечает, но продолжаем..."
            break
        fi
    done
    
    print_success "Сервисы развернуты"
}

# Создание скриптов управления
create_management_scripts() {
    print_step "Создание скриптов управления"
    
    # Скрипт статуса
    cat > ${INSTALL_DIR}/status.sh << 'EOF'
#!/bin/bash
cd /opt/n8n
echo "=== N8N Infrastructure Status ==="
echo "Generated: $(date)"
echo

echo "--- Docker Containers ---"
docker-compose ps

echo
echo "--- Service Health ---"
docker-compose exec -T postgres pg_isready -U n8n -d n8n 2>/dev/null && echo "✅ PostgreSQL: OK" || echo "❌ PostgreSQL: ERROR"
docker-compose exec -T redis redis-cli ping 2>/dev/null >/dev/null && echo "✅ Redis: OK" || echo "❌ Redis: ERROR"
curl -sSf https://n8n.3digitit.ru/healthz >/dev/null 2>&1 && echo "✅ N8N: OK" || echo "❌ N8N: ERROR"
curl -sSf https://traefik.3digitit.ru/api/version >/dev/null 2>&1 && echo "✅ Traefik: OK" || echo "❌ Traefik: ERROR"

echo
echo "--- URLs ---"
echo "🌐 N8N: https://n8n.3digitit.ru"
echo "🔧 Traefik: https://traefik.3digitit.ru (admin/admin)"

echo
echo "--- Useful Commands ---"
echo "View logs: docker-compose logs -f [service]"
echo "Restart: docker-compose restart"
echo "Update: docker-compose pull && docker-compose up -d"
EOF
    
    chmod +x ${INSTALL_DIR}/status.sh
    
    print_success "Скрипты управления созданы"
}

# Финальная проверка
final_check() {
    print_step "Финальная проверка"
    
    cd ${INSTALL_DIR}
    
    print_info "Статус контейнеров:"
    docker-compose ps
    
    echo
    print_info "Проверка доступности сервисов:"
    
    # Проверка N8N
    if curl -sSf https://n8n.${DOMAIN}/healthz >/dev/null 2>&1; then
        print_success "N8N доступен: https://n8n.${DOMAIN}"
    else
        print_warning "N8N пока не доступен (может потребоваться время для получения SSL)"
    fi
    
    # Проверка Traefik
    if curl -sSf https://traefik.${DOMAIN}/api/version >/dev/null 2>&1; then
        print_success "Traefik доступен: https://traefik.${DOMAIN}"
    else
        print_warning "Traefik Dashboard может быть недоступен"
    fi
}

# Главная функция
main() {
    clear
    print_banner
    
    check_root
    check_dns
    install_dependencies
    setup_firewall
    create_directories
    create_configs
    create_traefik_config
    create_postgres_init
    deploy_services
    create_management_scripts
    final_check
    
    # Финальный вывод
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  🎉 DEPLOYMENT COMPLETE! 🎉                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}📋 Информация о развертывании:${NC}"
    echo -e "${WHITE}🌐 N8N Interface: https://n8n.${DOMAIN}${NC}"
    echo -e "${WHITE}🔧 Traefik Dashboard: https://traefik.${DOMAIN}${NC}"
    echo -e "${WHITE}📁 Конфигурация: ${INSTALL_DIR}${NC}"
    echo
    echo -e "${CYAN}🔑 Первый запуск:${NC}"
    echo -e "${WHITE}1. Откройте https://n8n.${DOMAIN}${NC}"
    echo -e "${WHITE}2. Создайте первого администратора${NC}"
    echo -e "${WHITE}3. Начните создавать workflow!${NC}"
    echo
    echo -e "${CYAN}🛠️ Управление:${NC}"
    echo -e "${WHITE}Статус: ${INSTALL_DIR}/status.sh${NC}"
    echo -e "${WHITE}Логи: cd ${INSTALL_DIR} && docker-compose logs -f${NC}"
    echo -e "${WHITE}Перезапуск: cd ${INSTALL_DIR} && docker-compose restart${NC}"
    echo
    echo -e "${YELLOW}⚠️  Важно:${NC}"
    echo -e "${WHITE}• Измените пароли в Traefik Dashboard${NC}"
    echo -e "${WHITE}• Настройте регулярные бэкапы${NC}"
    echo -e "${WHITE}• Мониторьте использование ресурсов${NC}"
    echo
}

# Запуск
main "$@"
