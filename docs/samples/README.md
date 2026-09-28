# PortProof Sample Outputs

These files are genuine sample outputs from a single PortProof run against lab-only loopback test listeners.

## How the samples were generated

1. **Test environment:** Loopback addresses 127.0.0.2 and 127.0.0.3 only.
2. **Test listeners:** Two TCP listeners on ephemeral ports (33945 and 33946) accepting connections.
3. **Profile:** 8 rows with lab-only targets - a mix of open listeners and intentionally closed ports, plus one port 53 TCP probe.
4. **Tool invocation:** Built from src/ and run with:
   - -Profile lab-profile.csv (lab data only)
   - -Out <outdir> (output to temp directory)
   - -NoOperator (no real user/host captured)
   - -Format Html,Csv,Json (all output formats)
5. **Console output:** Captured with 6>&1 | Out-File -Encoding utf8 (genuine tool output, not reconstructed).

## Files included

- console.txt - Complete console output from the tool run, captured with real redirection.
- sample-report.html - HTML matrix report showing the probe results.
- sample-results.csv - CSV format of results with headers.
- sample-results.json - JSON format of results for integration scenarios.
- matrix.png - Full-page screenshot of the HTML report showing the matrix grid.

## Lab data notes

All addresses are 127.0.0.x loopback addresses. The tool correctly redacts OperatorUser and OperatorHost as "redacted" when -NoOperator is used.

The profile was designed to show a mix of outcomes:
- Some probes to open listeners (Pass/Open)
- Some probes to closed ports (Fail/Unreachable with Timeout)
- One inconclusive result (UDP with no response)
- One LocalPolicy result (TCP/53): the operator host's local policy (VPN DNS-leak protection) refuses outbound port 53, which the tool correctly reports as Inconclusive/LocalPolicy.

## run.gif

A looping animation of a separate lab run against loopback listeners (127.0.0.2 and 127.0.0.3),
also with -NoOperator, replaying the real captured console output line by line: the command typed,
then the run header, then the summary and exit code. It is not a screen recording - the frames are
rendered from the same console text a run produces, so nothing in it is reconstructed or invented.