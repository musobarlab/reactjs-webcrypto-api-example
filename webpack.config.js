var path = require('path');

module.exports = {
    entry: './src/crypsi/index.js',
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: 'crypsi.min.js',
        library: 'crypsi'
    },
    devtool: 'source-map'
};