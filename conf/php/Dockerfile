# To install PHP intl extension, need to run "apk add icu-dev" first, and it cannot be deleted after installation
# Then run "docker-php-ext-configure intl && docker-php-ext-install intl".  Will add ~43MB to image
# To install Wordpress site, need to add "docker-php-ext-install mysqli && docker-php-ext-enable mysqli"
FROM php:fpm-alpine
RUN apk add --no-cache libpng libpng-dev libjpeg-turbo-dev libwebp-dev zlib-dev libxpm-dev \
    && docker-php-ext-install gd \
    && apk del libpng-dev libjpeg-turbo-dev libwebp-dev zlib-dev libxpm-dev \
    && docker-php-ext-install pdo_mysql bcmath
