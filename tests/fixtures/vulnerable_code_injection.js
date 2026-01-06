/**
 * Test fixtures for code injection detection - JavaScript examples.
 *
 * Contains both vulnerable and safe code patterns for testing.
 */

// ============================================================================
// VULNERABLE PATTERNS - Should be detected
// ============================================================================

// 1. child_process.exec() - Command Injection
const { exec } = require('child_process');

function vulnerableChildProcessExec1() {
    const userInput = req.query.filename;
    exec(`cat ${userInput}`, (error, stdout, stderr) => {  // VULNERABLE
        console.log(stdout);
    });
}

function vulnerableChildProcessExec2() {
    const child_process = require('child_process');
    child_process.exec('rm -rf ' + userPath);  // VULNERABLE
}

function vulnerableChildProcessExec3() {
    require('child_process').exec(`ping ${hostname}`);  // VULNERABLE
}


// 2. eval() - Code Injection
function vulnerableEval1() {
    const userCode = req.body.expression;
    const result = eval(userCode);  // VULNERABLE
    return result;
}

function vulnerableEval2() {
    const mathExpr = getUserInput();
    eval(mathExpr);  // VULNERABLE
}

function vulnerableEval3() {
    eval("console.log('" + userInput + "')");  // VULNERABLE
}


// 3. Function() constructor - Dynamic Code Execution
function vulnerableFunctionConstructor1() {
    const userCode = req.body.code;
    const fn = new Function(userCode);  // VULNERABLE
    fn();
}

function vulnerableFunctionConstructor2() {
    const dynamicFunc = new Function('x', 'y', userExpression);  // VULNERABLE
    return dynamicFunc(1, 2);
}

function vulnerableFunctionConstructor3() {
    new Function(getCodeFromUser())();  // VULNERABLE
}


// ============================================================================
// SAFE PATTERNS - Should NOT be detected (or low confidence)
// ============================================================================

const { execFile, spawn } = require('child_process');

function safeExecFile() {
    // Safe: execFile doesn't spawn a shell
    execFile('ls', ['-la', directory], (error, stdout) => {  // SAFE
        console.log(stdout);
    });
}

function safeSpawn() {
    // Safe: spawn with array arguments
    spawn('echo', ['hello', userInput]);  // SAFE
}

function safeJsonParse() {
    // Safe: JSON.parse instead of eval
    const data = JSON.parse(userInput);  // SAFE
}

function safeNamedFunction() {
    // Safe: Named function, not Function constructor
    function myFunction() {
        return 'safe';
    }
}

// Comments should be ignored
// eval("this is just a comment")
// child_process.exec("example command")
// new Function("this is documentation")
/*
 * eval("multi-line comment")
 * exec("should be ignored")
 */
