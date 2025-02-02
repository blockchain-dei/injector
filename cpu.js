const path = require('path');
const fs = require('fs');
var osu = require('node-os-utils');
//const { end } = require('./tests/local-test/caliper/loadgen');

var cpu = osu.cpu;
var mem = osu.mem


var cpuStart=0;
//var cpuFinish = 0;
var memStart=0;
var memEnds=0;

cpuStart = checkCPU(500)
memStart = checkMem()
memStart.then(k => console.log(k))          

//cpuFinish = checkCPU(30000);
memEnds = checkMem()
memEnds.then(k => console.log(k))  

console.log('CPU Start')
cpuStart.then( j=> {console.log(j)})

console.log(memEnds)
//console.log('CPU Ends')
//cpuFinish.then(j=> {console.log(j)})

//console.log('Mem Start')
//memStart.then(j=> {console.log(j)})
//console.log('Mem Ends')
//memFinish.then(j=> {console.log(j)})


const outputDir = path.join(__dirname, 'outputs');

writeStream = fs.createWriteStream(`test.csv`);

 setWriteCpu(cpuStart)
 setWriteMem(memStart,memEnds)


//memStart.then(j=> { writeStream.write(`${1};mem_start;${j}\n`, function(err) { writeStream.end(); } );})  
//memEnds.then(j=> { writeStream.write(`${2};mem_end;${j}\n`,  function(err) { writeStream.end(); });})  



module.exports.end = async () => {
    await util.sleep(2000); // wait for flushing every tx data
    writeStream.end();
};

async function checkCPU(interval) {
    const cpuUsage =  cpu.usage(interval);
    return (cpuUsage);
   }

   async function checkMem() {
    const memUsage = await mem.info();
    return  (memUsage['usedMemMb'] );
   }

   async function setWriteCpu(cpuUsage) {
   await cpuUsage.then( j=> { writeStream.write(`${3};cpu_usage;${j}\n`);})


    return (true);
   }

   async function setWriteMem(memStart,memEnd) {
    await memStart.then( j=> { writeStream.write(`${3};mem_start;${j}\n`);})
    await memEnd.then( j=> { writeStream.write(`${3};mem_end;${j}\n`);})
 
 
     return (true);
    }
 
