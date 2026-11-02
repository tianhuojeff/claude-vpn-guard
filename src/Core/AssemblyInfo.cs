// written_by: claude-code
// 声明目标框架为 .NET Framework 4.8：使运行时启用现代默认值（TLS 1.2/1.3 由系统决定，而不是旧的 SSL3/TLS1.0）。
using System.Reflection;
using System.Runtime.Versioning;

[assembly: TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
[assembly: AssemblyProduct("Claude VPN Guard")]
[assembly: AssemblyCompany("tianhuojeff")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
