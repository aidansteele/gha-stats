const { execSync } = require('child_process');
const artifact = require('@actions/artifact');

(async () => {
  try {
    execSync(`ls -lh /tmp 1>&2`);
    execSync(`gha-stats stop 1>&2`);
  } finally {
    const client = artifact.create();
    const result = await client.uploadArtifact('gha-stats', ['/tmp/gha.log'], '/tmp');
  }
})();
