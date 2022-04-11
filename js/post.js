const { execSync } = require('child_process');
const artifact = require('@actions/artifact');

(async () => {
  execSync(`gha-stats stop 1>&2`);
  const client = artifact.create();
  const result = await client.uploadArtifact('gha-stats', ['/tmp/gha.log'], '/tmp');
})();
