curl --cert-type P12 --cert client.p12:password \
     --key-type P12 --key client.p12:password \
     https://your-api.example.com/deploy

curl --cert client.p12:password https://your-api.example.com/deploy
