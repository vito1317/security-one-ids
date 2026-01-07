FROM php:8.3-fpm-alpine

# Install system dependencies
RUN apk add --no-cache \
    nginx \
    supervisor \
    curl \
    libpng-dev \
    libxml2-dev \
    zip \
    unzip \
    git \
    shadow

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql bcmath gd xml

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /var/www/html

# Copy application files
COPY . /var/www/html

# Install composer dependencies
RUN composer install --optimize-autoloader --no-dev --no-interaction

# Create directories and set permissions
RUN mkdir -p /var/www/html/storage/logs \
    && mkdir -p /var/www/html/bootstrap/cache \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 775 /var/www/html/storage \
    && chmod -R 775 /var/www/html/bootstrap/cache

# Configure Nginx
COPY docker/nginx.conf /etc/nginx/http.d/default.conf

# Configure Supervisor
COPY docker/supervisord.conf /etc/supervisor.d/supervisord.ini

# Expose port
EXPOSE 80

# Start Supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
