# Identity service. Build context: the repository root.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Restore first so the layer is cached until a project file changes.
COPY global.json ./
COPY src/Identity.Api/Identity.Api.csproj src/Identity.Api/
RUN dotnet restore src/Identity.Api/Identity.Api.csproj

COPY src ./src
RUN dotnet publish src/Identity.Api/Identity.Api.csproj -c Release -o /out --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /out .

# Non-root (APP_UID is defined by the base image), no diagnostics port, plain HTTP inside the container:
# TLS terminates at the ingress (Azure Container Apps / a reverse proxy).
ENV ASPNETCORE_URLS=http://+:8080 \
    DOTNET_EnableDiagnostics=0
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "Identity.Api.dll"]
