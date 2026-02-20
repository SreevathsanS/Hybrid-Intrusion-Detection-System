//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract IDSLogStorage{

    //-------------------------------
    //Structure to store IDS Logs
    //-------------------------------
    struct IDSLog{
        uint256 timestamp;
        string srcIP;
        string dstIP;
        string protocol;
        string prediction;
        string attackType;
        string logHash;
    }

    // Array to store Logs
    IDSLog[] private logs;

    //Event for monitoring log IDSLog Storage
    
    event LogStored(
        uint256 timestamp,
        string srcIP,
        string dstIP,
        string prediction
    );
    //--------------------------------
    //Store IDS Log on Blockchain
    //--------------------------------

    function storeLog(
        string memory _srcIP,
        string memory _dstIP,
        string memory _protocol,
        string memory _prediction,
        string memory _attackType,
        string memory _logHash
    ) public {

        IDSLog memory newLog = IDSLog({
            timestamp: block.timestamp,
            srcIP: _srcIP,
            dstIP: _dstIP,
            protocol: _protocol,
            prediction: _prediction,
            attackType: _attackType,
            logHash: _logHash
        });

        logs.push(newLog);

        emit LogStored(
            block.timestamp,
            _srcIP,
            _dstIP,
            _prediction
        );
    }

    //------------------------------
    // get total number of logs
    //------------------------------
    function getLogCount() public view returns (uint256){
        return logs.length;
    }

    //-----------------------------
    //Retrive a specific log
    //-----------------------------
    function getLog(uint256 index)
    public view returns (
        uint256,
        string memory,
        string memory,
        string memory,
        string memory,
        string memory,
        string memory
    )
    {
        require(index < logs.length, "Invalid Log index");
        
        IDSLog memory log = logs[index];

        return(
            log.timestamp,
            log.srcIP,
            log.dstIP,
            log.protocol,
            log.prediction,
            log.attackType,
            log.logHash
        );
    }

}