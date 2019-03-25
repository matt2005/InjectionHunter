function RunRuleForCommand
{
    param([String] $Command)

    $outputPath = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName() + ".ps1")
    try
    {
        Set-Content -Path $outputPath -Value $Command

        Invoke-ScriptAnalyzer -Path $outputPath `
            -CustomizedRulePath (Resolve-Path $PSScriptRoot\..\InjectionHunter.psm1) `
            -ExcludeRule PS*

    }
    finally
    {
        Remove-Item $outputPath
    }
}

Describe "Tests for expression injection" {

    It "Should detect Invoke-Expression" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                Invoke-Expression "Get-Process -Name $UserInput"
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-InvokeExpression"
    }

    It "Should detect Invoke-Expression alias" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                iex "Get-Process -Name $UserInput"
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-InvokeExpression"
    }

    It "Should detect InvokeScript" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                $executionContext.InvokeCommand.InvokeScript("Get-Process -Name $UserInput")
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-DangerousMethod"
    }

    It "Should detect CreateNestedPipeline" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                $host.Runspace.CreateNestedPipeline("Get-Process -Name $UserInput", $false).Invoke()
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-DangerousMethod"
    }

    It "Should detect AddScript" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                [PowerShell]::Create().AddScript("Get-Process -Name $UserInput").Invoke()
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-DangerousMethod"
    }
}

Describe "Tests for code injection" {

    It "Should detect Add-Type injection" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                Add-Type "public class Foo { $UserInput }"
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-AddType"
    }

    It "Should detect Add-Type injection w/ parameter" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                Add-Type -TypeDefinition "public class Foo { $UserInput }"
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-AddType"
    }

    It "Should detect Add-Type injection w/ variable" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)

                $code = "public class Foo { $UserInput }"
                Add-Type -TypeDefinition $code
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-AddType"
    }

    It "Should allow Add-Type w/ constant expression variable" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)

                $code = "public class Foo { Bar }"
                Add-Type -TypeDefinition $code
            }
        }
        $result | Should be $null
    }

    It "Should allow Add-Type w/ constant expression inline" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)

                Add-Type -TypeDefinition "public class Foo { Bar }"
            }
        }
        $result | Should be $null
    }
}


Describe "Tests for command injection" {

    It "Should detect PowerShell injection" {
        $result = RunRuleForCommand {
            function Invoke-ExploitableCommandInjection
            {
                param($UserInput)

                powershell -command "Get-Process -Name $UserInput"
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-CommandInjection"
    }

    It "Should detect PowerShell injection w/o parameter" {
        $result = RunRuleForCommand {
            function Invoke-ExploitableCommandInjection
            {
                param($UserInput)

                powershell "Get-Process -Name $UserInput"
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-CommandInjection"
    }

    It "Should detect CMD injection" {
        $result = RunRuleForCommand {
            function Invoke-ExploitableCommandInjection
            {
                param($UserInput)

                cmd /c "ping $UserInput"
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-CommandInjection"
    }

    It "Should allow non-injected commands" {
        $result = RunRuleForCommand {
            function Invoke-ExploitableCommandInjection
            {
                param($UserInput)

                cmd /c "ping localhost"
            }
        }
        $result | Should be $null
    }
}

Describe "Tests for script block injection" {

    It "Should detect ScriptBlock.Create injection" {
        $result = RunRuleForCommand {
            function Invoke-ScriptBlockInjection
            {
                param($UserInput)

                ## Often used when making remote connections

                $sb = [ScriptBlock]::Create("Get-Process -Name $UserInput")
                Invoke-Command RemoteServer $sb
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-DangerousMethod"
    }

    It "Should detect NewScriptBlock injection" {
        $result = RunRuleForCommand {
            function Invoke-ScriptBlockInjection
            {
                param($UserInput)

                ## Often used when making remote connections

                $sb = $executionContext.InvokeCommand.NewScriptBlock("Get-Process -Name $UserInput")
                Invoke-Command RemoteServer $sb
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-DangerousMethod"
    }
}

Describe "Tests for method injection" {

    It "Should detect Foreach-Object injection" {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                param($UserInput)

                Get-Process | Foreach-Object $UserInput
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-ForeachObjectInjection"
    }

    It "Should allow Foreach-Object w/ script block" {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                param($UserInput)

                Get-Process | Foreach-Object { $_.Name }
            }
        }
        $result | Should be $null
    }

    It "Should allow Foreach-Object w/ constant member access" {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                param($UserInput)

                Get-Process | Foreach-Object "Name"
            }
        }
        $result | Should be $null
    }

    It "Should detect static property injection" {
        $result = RunRuleForCommand {
            function Invoke-PropertyInjection
            {
                param($UserInput)

                [DateTime]::$UserInput
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-PropertyInjection"
    }

    It "Should detect method injection w/ parens" {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                param($UserInput)

                (Get-Process -Id $pid).$UserInput()
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-MethodInjection"
    }

    It "Should detect method injection w/ Invoke" {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                param($UserInput)

                (Get-Process -Id $pid).$UserInput.Invoke()
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-PropertyInjection"
    }

}

Describe "Tests for string expansion injection" {

    It "Should detect ExpandString injection via ExecutionContext" {
        $result = RunRuleForCommand {
            function Invoke-ExpandStringInjection
            {
                param($UserInput)

                ## Used to attempt a variable resolution
                $executionContext.InvokeCommand.ExpandString($UserInput)
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-DangerousMethod"
    }

    It "Should detect ExpandString injection via SessionState" {
        $result = RunRuleForCommand {
            function Invoke-ExpandStringInjection
            {
                param($UserInput)

                ## Used to attempt a variable resolution
                $executionContext.SessionState.InvokeCommand.ExpandString($UserInput)
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-DangerousMethod"
    }

}

Describe "Tests for unsafe excaping" {

    It "Should detect unsafe escaping - single quotes" {
        $result = RunRuleForCommand {
            function Invoke-UnsafeEscape
            {
                param($UserInput)

                $escaped = $UserInput -replace "'", "''"
                Invoke-ExpressionHelper "Get-Process -Name '$escaped'"
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-UnsafeEscaping"
    }

    It "Should detect unsafe escaping - double quotes" {
        $result = RunRuleForCommand {
            function Invoke-UnsafeEscape
            {
                param($UserInput)

                $escaped = $UserInput -replace '"', '`"'
                Invoke-ExpressionHelper "Get-Process -Name `"$escaped`""
            }
        }
        $result.RuleName | Should be "InjectionHunter\Measure-UnsafeEscaping"
    }

}

Describe -Name "Tests for supression of rules" -Fixture {
    It -Name 'Measure-InvokeExpression' -Test {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-InvokeExpression', '', Justification = "Pester Test Validation")]
                param($UserInput)
                Invoke-Expression "Get-Process -Name $UserInput"
            }
        }
        $result.RuleName | Should -BeNullOrEmpty
    }
    It -Name 'Measure-AddType' -Test {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-AddType', '', Justification = "Pester Test Validation")]
                param($UserInput)
                Add-Type "public class Foo { $UserInput }"
            }
        }
        $result.RuleName | Should -BeNullOrEmpty
    }
    It -Name 'Measure-DangerousMethod' -Test {
        $result = RunRuleForCommand {
            function Invoke-ScriptBlockInjection
            {
                [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-DangerousMethod', '', Justification = "Pester Test Validation")]
                param($UserInput)

                ## Often used when making remote connections

                $sb = [ScriptBlock]::Create("Get-Process -Name $UserInput")
                Invoke-Command RemoteServer $sb
            }
        }
        $result.RuleName | Should -BeNullOrEmpty
    }
    It -Name 'Measure-CommandInjection' -Test {
        $result = RunRuleForCommand {
            function Invoke-ExploitableCommandInjection
            {
                [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-CommandInjection', '', Justification = "Pester Test Validation")]
                param($UserInput)

                powershell -command "Get-Process -Name $UserInput"
            }
        }
        $result.RuleName | Should -BeNullOrEmpty
    }
    It -Name 'Measure-ForeachObjectInjection' -Test {
        $result = RunRuleForCommand {
            function Invoke-ForeachObjectInjection
            {
                [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-ForeachObjectInjection', '', Justification = "Pester Test Validation")]
                param($UserInput)

                Get-Process | Foreach-Object $UserInput
            }
        }
        $result.RuleName | Should -BeNullOrEmpty
    }
    It -Name 'Measure-PropertyInjection' -Test {
        $result = RunRuleForCommand {
            function Invoke-PropertyInjection
            {
                [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-PropertyInjection', '', Justification = "Pester Test Validation")]
                param($UserInput)

                [DateTime]::$UserInput
            }
        }
        $result.RuleName | Should -BeNullOrEmpty
    }
    It -Name 'Measure-MethodInjection' -Test {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-MethodInjection', '', Justification = "Pester Test Validation")]
                param($UserInput)

                (Get-Process -Id $pid).$UserInput()
            }
        }
        $result.RuleName | Should -BeNullOrEmpty
    }
    It -Name 'Measure-UnsafeEscaping' -Test {
        $result = RunRuleForCommand {
            function Invoke-UnsafeEscape
            {
                [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-UnsafeEscaping', '', Justification = "Pester Test Validation")]
                param($UserInput)

                $escaped = $UserInput -replace "'", "''"
                Invoke-ExpressionHelper "Get-Process -Name '$escaped'"
            }
        }
        $result.RuleName | Should -BeNullOrEmpty
    }
}