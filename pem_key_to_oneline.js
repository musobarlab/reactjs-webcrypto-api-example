const readline = require('readline');
const fs = require('fs');
const path = require('path');

function main() {
    const args = process.argv;
    if (args.length <= 2) {
        console.log('required pem file argument');
        process.exit(1);
    }

    const pemFileArg = args[2];
    const cwd = process.cwd();
    const pemPath = path.join(cwd, pemFileArg);

    if (!fs.existsSync(pemPath)) {
        console.log('pem file does not exist');
        process.exit(1);
    }

    const pemOut = path.join(cwd, `${pemFileArg}.oneline.txt`);

    try {
        const outStream = fs.createWriteStream(pemOut, )
        const rl = readline.createInterface({
            input: fs.createReadStream(pemPath)
        });

        rl.on('line', (line) => {
            outStream.write(line);
            outStream.write('\\n');
        });

        rl.on('close', () => {
            outStream.end();
        });

        

    } catch(err) {
        console.log(err);
        process.exit(1);
    }
}

main();