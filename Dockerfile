FROM php:8.3-fpm-alpine

# Install system dependencies + ClamAV
RUN apk add --no-cache \
    nginx \
    supervisor \
    curl \
    libpng-dev \
    libxml2-dev \
    zip \
    unzip \
    git \
    shadow \
    sqlite \
    sqlite-dev \
    clamav \
    clamav-libunrar

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql pdo_sqlite bcmath gd xml

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /var/www/html

# Copy composer files first for better caching
COPY composer.json composer.lock ./

# Configure git safe directory and install dependencies
RUN git config --global --add safe.directory /var/www/html \
    && composer install --optimize-autoloader --no-dev --no-interaction --no-scripts

# Copy application files
COPY . /var/www/html

# Run composer dump-autoload
RUN composer dump-autoload --optimize --no-dev

# Create directories and set permissions
RUN mkdir -p /var/www/html/storage/logs \
    && mkdir -p /var/www/html/storage/framework/sessions \
    && mkdir -p /var/www/html/storage/framework/views \
    && mkdir -p /var/www/html/storage/framework/cache \
    && mkdir -p /var/www/html/bootstrap/cache \
    && mkdir -p /var/www/html/database \
    && mkdir -p /var/log/supervisor \
    && mkdir -p /var/lib/clamav \
    && touch /var/www/html/database/database.sqlite \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 775 /var/www/html/storage \
    && chmod -R 775 /var/www/html/bootstrap/cache \
    && chmod -R 755 /var/log/supervisor \
    && chmod 664 /var/www/html/database/database.sqlite \
    && chmod -R 775 /var/www/html/database \
    && chown -R clamav:clamav /var/lib/clamav \
    && chmod -R 755 /var/lib/clamav

# Configure ClamAV freshclam
RUN sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf 2>/dev/null || true

# Configure Nginx
COPY docker/nginx.conf /etc/nginx/http.d/default.conf

# Configure Supervisor
COPY docker/supervisord.conf /etc/supervisor.d/supervisord.ini

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

# Start Supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
