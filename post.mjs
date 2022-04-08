import { execSync } from 'child_process';

console.log("post 1");
execSync(`ls -lh /tmp`);
execSync(`gha-stats stop`);
console.log("post 2");
