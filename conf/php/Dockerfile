# Use `install-php-extensions` script is easier but the final image size is bigger
# FROM php:7.2-cli
# ADD --chmod=0755 https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions /usr/local/bin/
# RUN install-php-extensions gd xdebug

# To add PHP intl extension
# `apk add icu-dev && docker-php-ext-configure intl && docker-php-ext-install intl`
# "icu-dev" CANNOT be deleted after installation. Add ~43MB to image

# To install Wordpress site
# `docker-php-ext-install mysqli && docker-php-ext-enable mysqli`

# To add PostgreSQL support
# `apk add postgresql-libs postgresql-dev && docker-php-ext-install pgsql pdo_pgsql && apk del postgresql-dev`
# Add ~12MB to image.  "pgsql" is optional if only use PDO, but only add ~0.2MB

# To add imagick extension
# `apk add autoconf g++ make imagemagick-dev && pecl install imagick && docker-php-ext-enable imagick && rm -rf /tmp/pear && apk del g++ make`
# "imagemagick-dev" CANNOT be deleted after installation.  Add ~17MB to image

# To add zip extension
# `apk add zip libzip-dev && docker-php-ext-configure zip && docker-php-ext-install zip`
# Add ~2MB to image

# To add soap extension
# `apk add libxml2-dev && docker-php-ext-install soap`
# Add ~1MB to image

# To add exif extension
# `docker-php-ext-install exif`
# Add <1MB to image

# To add opcache extension
# `docker-php-ext-install opcache`
# Add ~1MB to image

FROM php:fpm-alpine
RUN apk add --no-cache libpng libpng-dev libjpeg-turbo-dev libwebp-dev zlib-dev libxpm-dev \
    && docker-php-ext-install gd bcmath pdo_mysql \
    && apk del libpng-dev libjpeg-turbo-dev libwebp-dev zlib-dev libxpm-dev
