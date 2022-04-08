import { execSync } from 'child_process';

console.log("post 1");
execSync(`ls -lh /tmp 1>&2`);
execSync(`gha-stats stop 1>&2`);
console.log("post 2");
