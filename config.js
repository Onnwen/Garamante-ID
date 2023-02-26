const mariadb = require('mariadb');
const pool = mariadb.createPool({
    host: '52.47.52.89',
    user:'admin',
    password: 'lpgbFc2d#9N0',
    database: 'GaramanteID'
});

module.exports = pool;