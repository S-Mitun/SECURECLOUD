import { defineRailway, github, project, service } from "railway/iac";

export default defineRailway(() => {
  const SecureCloudApp = service("SecureCloud-App", {
    source: github("S-Mitun/SecureCloud-App", { checkSuites: false }),
    replicas: { "ams": 1 },
    networking: { privateNetworkEndpoint: "securecloud-app" },
  });

  return project("brave-imagination", {
    resources: [SecureCloudApp],
  });
});
