const { execSync } = require('child_process');
const core = require('@actions/core');

const apiKey = core.getInput("honeycombApiKey", { required: true });
const dataset = core.getInput("honeycombDataset", { required: true });
const interval = core.getInput("interval", { required: false }) || "5s";

const url = "https://github.com/aidansteele/gha-stats/releases/download/v0.3.0/gha-stats_0.3.0_linux_amd64.tar.gz";
execSync(`curl -o /tmp/gha-stats.tgz -L ${url}`);
execSync(`sudo tar -C /usr/bin -xvf /tmp/gha-stats.tgz`);
execSync(`gha-stats start ${interval}`, {
  env: {
    ...process.env,
    HONEYCOMB_API_KEY: apiKey,
    HONEYCOMB_DATASET: dataset,
  }
});
