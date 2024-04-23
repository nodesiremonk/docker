# To install PHP intl extension, need to run "apk add icu-dev" first, and it CANNOT be deleted after installation
# Then run "docker-php-ext-configure intl && docker-php-ext-install intl".  Will add ~43MB to image

# To install Wordpress site, need to add "docker-php-ext-install mysqli && docker-php-ext-enable mysqli"

# To add PostgreSQL support, need to run "apk add postgresql-libs postgresql-dev" then "docker-php-ext-install pgsql pdo_pgsql".
# "postgresql-dev" can be deleted after installation.  Will add ~12MB to image.  "pgsql" is optional if only use PDO, but only add ~0.2MB

# To add imagick extension, need to "apk add autoconf g++ make imagemagick-dev \ 
# && pecl install imagick && docker-php-ext-enable imagick && rm -rf /tmp/pear && apk del g++ make
# and "imagemagick-dev" CANNOT be deleted after installation

FROM php:fpm-alpine
RUN apk add --no-cache libpng libpng-dev libjpeg-turbo-dev libwebp-dev zlib-dev libxpm-dev \
    && docker-php-ext-install gd bcmath pdo_mysql \
    && apk del libpng-dev libjpeg-turbo-dev libwebp-dev zlib-dev libxpm-dev
