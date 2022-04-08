import { execSync } from 'child_process';

execSync(`ls -lh /tmp`);
execSync(`gha-stats stop`);
