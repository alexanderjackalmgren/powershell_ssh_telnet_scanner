# Requires -Version 5.1
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Main Window Form ---
$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Network Port Scanner (SSH / Telnet)"
$Form.Size = New-Object System.Drawing.Size(600, 460)
$Form.StartPosition = "CenterScreen"
$Form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 36)
$Form.FormBorderStyle = "FixedSingle"
$Form.MaximizeBox = $false

# --- Font Style ---
$UIFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$LogFont = New-Object System.Drawing.Font("Consolas", 9)

# --- Subnet Label ---
$LblSubnet = New-Object System.Windows.Forms.Label
$LblSubnet.Text = "Target Subnet (CIDR):"
$LblSubnet.Location = New-Object System.Drawing.Point(15, 20)
$LblSubnet.Size = New-Object System.Drawing.Size(150, 25)
$LblSubnet.ForeColor = [System.Drawing.Color]::White
$LblSubnet.Font = $UIFont
$Form.Controls.Add($LblSubnet)

# --- Subnet TextBox ---
$TxtSubnet = New-Object System.Windows.Forms.TextBox
$TxtSubnet.Text = "192.168.0.0/24"
$TxtSubnet.Location = New-Object System.Drawing.Point(165, 17)
$TxtSubnet.Size = New-Object System.Drawing.Size(180, 25)
$TxtSubnet.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 52)
$TxtSubnet.ForeColor = [System.Drawing.Color]::White
$TxtSubnet.BorderStyle = "FixedSingle"
$Form.Controls.Add($TxtSubnet)

# --- Start Scan Button ---
$BtnScan = New-Object System.Windows.Forms.Button
$BtnScan.Text = "Start Scan"
$BtnScan.Location = New-Object System.Drawing.Point(360, 16)
$BtnScan.Size = New-Object System.Drawing.Size(100, 27)
$BtnScan.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$BtnScan.ForeColor = [System.Drawing.Color]::White
$BtnScan.FlatStyle = "Flat"
$BtnScan.FlatAppearance.BorderSize = 0
$BtnScan.Font = $UIFont
$Form.Controls.Add($BtnScan)

# --- Progress Bar ---
$ProgBar = New-Object System.Windows.Forms.ProgressBar
$ProgBar.Location = New-Object System.Drawing.Point(15, 60)
$ProgBar.Size = New-Object System.Drawing.Size(465, 15)
$Form.Controls.Add($ProgBar)

# --- Progress Counter Text ---
$TxtProgress = New-Object System.Windows.Forms.Label
$TxtProgress.Text = "0 / 0 IPs"
$TxtProgress.Location = New-Object System.Drawing.Point(490, 58)
$TxtProgress.Size = New-Object System.Drawing.Size(80, 20)
$TxtProgress.ForeColor = [System.Drawing.Color]::FromArgb(170, 170, 170)
$TxtProgress.TextAlign = "MiddleRight"
$Form.Controls.Add($TxtProgress)

# --- Log Box ---
$TxtLog = New-Object System.Windows.Forms.TextBox
$TxtLog.Multiline = $true
$TxtLog.ScrollBars = "Vertical"
$TxtLog.ReadOnly = $true
$TxtLog.Location = New-Object System.Drawing.Point(15, 90)
$TxtLog.Size = New-Object System.Drawing.Size(555, 280)
$TxtLog.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 20)
$TxtLog.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 102)
$TxtLog.BorderStyle = "FixedSingle"
$TxtLog.Font = $LogFont
$Form.Controls.Add($TxtLog)

# --- Status Footer Bar ---
$TxtStatus = New-Object System.Windows.Forms.Label
$TxtStatus.Text = "Ready"
$TxtStatus.Location = New-Object System.Drawing.Point(15, 385)
$TxtStatus.Size = New-Object System.Drawing.Size(555, 20)
$TxtStatus.ForeColor = [System.Drawing.Color]::FromArgb(136, 136, 136)
$Form.Controls.Add($TxtStatus)

# --- UI Button Click Action ---
$BtnScan.Add_Click({
    $Subnet = $TxtSubnet.Text.Trim()
    if ($Subnet -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
        [System.Windows.Forms.MessageBox]::Show("Please enter a valid CIDR format (e.g., 192.168.0.0/24)", "Invalid Input", "OK", "Error")
        return
    }

    $BtnScan.Enabled = $false
    $TxtSubnet.Enabled = $false
    $TxtLog.Clear()
    $TxtStatus.Text = "Parsing subnet..."
    [System.Windows.Forms.Application]::DoEvents()

    try {
        # Subnet Conversion
        $IpAddress, $MaskBits = $Subnet.Split('/')
        $MaskBits = [int]$MaskBits
        $IpBytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
        [Array]::Reverse($IpBytes)
        $IpAsInt = [System.BitConverter]::ToUInt32($IpBytes, 0)
        $Mask = [uint32]::MaxValue -shl (32 - $MaskBits)
        $NetworkAddress = $IpAsInt -band $Mask
        $NumberOfHosts = [Math]::Pow(2, (32 - $MaskBits))

        $IpList = for ($i = 0; $i -lt $NumberOfHosts; $i++) {
            $CurrentIpInt = $NetworkAddress + $i
            $CurrentIpBytes = [System.BitConverter]::GetBytes($CurrentIpInt)
            [Array]::Reverse($CurrentIpBytes)
            ([System.Net.IPAddress]$CurrentIpBytes).IPAddressToString
        }

        $TotalIPs = $IpList.Count
        $ProgBar.Maximum = $TotalIPs
        $ProgBar.Value = 0
        $TxtProgress.Text = "0 / $TotalIPs"
        $TxtStatus.Text = "Scanning..."
        [System.Windows.Forms.Application]::DoEvents()

        # --- Runspace Pool Engine ---
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 50)
        $RunspacePool.Open()
        $Jobs = [System.Collections.Generic.List[PSCustomObject]]::new()

        $ScriptBlock = {
            param($TargetIP)
            $Ports = @(22, 23)
            $Timeout = 1000
            $Lines = [System.Collections.Generic.List[string]]::new()

            foreach ($Port in $Ports) {
                $TcpClient = New-Object System.Net.Sockets.TcpClient
                $Connect = $TcpClient.BeginConnect($TargetIP, $Port, $null, $null)
                $Wait = $Connect.AsyncWaitHandle.WaitOne($Timeout, $true)
                $Service = if ($Port -eq 22) { "SSH" } else { "Telnet" }

                if ($Wait -and $TcpClient.Connected) {
                    $Status = "OPEN"
                    $TcpClient.EndConnect($Connect)
                } else {
                    $Status = "CLOSED/TIMEOUT"
                }
                $TcpClient.Close(); $TcpClient.Dispose()
                $Lines.Add(("[{0}] IP: {1,-15} | Port: {2,-2} ({3,-6}) | Status: {4}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $TargetIP, $Port, $Service, $Status))
            }
            return $Lines
        }

        foreach ($IP in $IpList) {
            $PowershellInstance = [powershell]::Create().AddScript($ScriptBlock).AddArgument($IP)
            $PowershellInstance.RunspacePool = $RunspacePool
            $Jobs.Add([PSCustomObject]@{
                Instance = $PowershellInstance
                Handle   = $PowershellInstance.BeginInvoke()
            })
        }

        $FinalOutput = [System.Collections.Generic.List[string]]::new()
        $CompletedCount = 0

        while ($Jobs.Count -gt 0) {
            $FinishedJobs = $Jobs | Where-Object { $_.Handle.IsCompleted }
            foreach ($Job in $FinishedJobs) {
                $Lines = $Job.Instance.EndInvoke($Job.Handle)
                foreach ($Line in $Lines) {
                    $TxtLog.AppendText("$Line`r`n")
                    $FinalOutput.Add($Line)
                }
                $Job.Instance.Dispose()
                $Jobs.Remove($Job) | Out-Null
                
                $CompletedCount++
                $ProgBar.Value = $CompletedCount
                $TxtProgress.Text = "$CompletedCount / $TotalIPs"
                $TxtLog.SelectionStart = $TxtLog.Text.Length
                $TxtLog.ScrollToCaret()
                [System.Windows.Forms.Application]::DoEvents()
            }
            Start-Sleep -Milliseconds 50
        }

        $RunspacePool.Close(); $RunspacePool.Dispose()

        # --- File Output Handling ---
        $OutputDir = "C:\temp"
        if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
        $FinalOutput | Out-File -FilePath "$OutputDir\PortScanResults.txt" -Encoding utf8

        $TxtStatus.Text = "Scan Complete! Results written to C:\temp\PortScanResults.txt"

    } catch {
        $TxtLog.AppendText("Error: $_`r`n")
        $TxtStatus.Text = "Scan failed due to an error."
    } finally {
        $BtnScan.Enabled = $true
        $TxtSubnet.Enabled = $true
    }
})

# Display Window
$Form.ShowDialog() | Out-Null