FROM node:18 AS build

WORKDIR /app

COPY package.json ./
COPY yarn.lock ./
RUN yarn install
COPY . ./
RUN yarn build

FROM nginx:1.19-alpine
COPY --from=build /app/dist /usr/share/nginx/html