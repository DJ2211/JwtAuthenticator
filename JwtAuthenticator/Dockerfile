FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY JwtAuthenticator.csproj .
RUN dotnet restore

COPY . .
RUN dotnet publish -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

RUN mkdir -p /app/data && chown -R $APP_UID:$APP_UID /app/data

USER $APP_UID

EXPOSE 8080

COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "JwtAuthenticator.dll"]