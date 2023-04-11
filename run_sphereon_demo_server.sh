
#!/bin/bash

git clone https://github.com/impierce/SIOPv2-OpenID4VP-example.git sphereon_demo_server && cd sphereon_demo_server;
npm install -g pnpm;
pnpm install;
pnpm build;
pnpm start:dev;
