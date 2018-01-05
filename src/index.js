const {main}=require('./cli');

if (require.main == module) main(process.argv.slice(2));
