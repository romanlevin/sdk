const path = require('path');

module.exports = {
  mode: 'development',
  entry: [ './src/index.js', './src/VaccinationSample/index.js' ],
  output: {
    path: path.resolve(__dirname, './src'),
    filename: 'bundle.js',
  }
};