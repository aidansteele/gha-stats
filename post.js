import { execSync } from 'child_process';

const path = "/usr/bin/gha-stats"
execSync(`${path} stop`);
