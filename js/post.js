import { execSync } from 'child_process';
import artifact from '@actions/artifact';

(async () => {
  console.log("post 1");

  execSync(`ls -lh /tmp 1>&2`);
  execSync(`gha-stats stop 1>&2`);

  const client = artifact.create();
  const result = await client.uploadArtifact('gha-stats', ['/tmp/gha.log'], '/tmp');

  console.log("post 2");
})();
