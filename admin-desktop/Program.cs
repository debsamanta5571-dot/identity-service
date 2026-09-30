using System.Diagnostics;

namespace IdentityAdmin;

internal static class Program
{
    private const string DefaultServer = "http://localhost:5001";

    [STAThread]
    private static int Main(string[] args)
    {
        var server = DefaultServer;
        for (var i = 0; i < args.Length - 1; i++)
            if (args[i] is "--server" or "--selftest") server = args[i + 1];

        // Headless check of the real sign-in + API path, used by tests and CI-style smoke runs:
        //   IdentityAdmin.exe --selftest http://localhost:5001      (prints the sign-in URL and waits for the callback)
        if (args.Contains("--selftest")) return SelfTest.RunAsync(server).GetAwaiter().GetResult();

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm(server));
        return 0;
    }
}

internal static class SelfTest
{
    public static async Task<int> RunAsync(string server)
    {
        try
        {
            // 1. the window builds without throwing (all controls, layout and event wiring)
            using (var form = new MainForm(server)) form.CreateControl();
            // Creating a control installs a WinForms synchronization context on this thread. This headless run never
            // pumps messages, so remove it, or every await below would wait for a UI thread that is not running.
            SynchronizationContext.SetSynchronizationContext(null);
            Console.WriteLine("OK window constructed");

            // 2. real sign-in: the URL is printed so a script can play the browser
            var auth = new AuthClient(server, url => { Console.WriteLine("AUTHORIZE_URL " + url); Console.Out.Flush(); });
            await auth.SignInAsync();
            Console.WriteLine($"OK signed in as {auth.Email}");

            // 3. create an account through the admin API, find it, disable it, enable it again
            var api = new ApiClient(auth);
            var roles = await api.RolesAsync();
            Console.WriteLine($"OK roles: {string.Join(", ", roles.Select(r => r.Name))}");

            var email = $"selftest-{Guid.NewGuid():N}@example.com";
            var password = MainForm.NewPassword();
            var created = await api.CreateUserAsync(email, "Self Test", password, ["operator"]);
            Console.WriteLine($"OK created {created.Email} roles=[{string.Join(",", created.Roles)}] active={created.IsActive}");

            var found = (await api.UsersAsync(email, 1, 10)).Items.Single();
            Console.WriteLine($"OK found it in the list (id {found.Id})");

            var disabled = await api.SetActiveAsync(found.Id, false);
            var enabled = await api.SetActiveAsync(found.Id, true);
            Console.WriteLine($"OK disable -> active={disabled.IsActive}, enable -> active={enabled.IsActive}");

            try { await api.CreateUserAsync(email, "Duplicate", password, []); Console.WriteLine("FAIL duplicate was accepted"); return 1; }
            catch (ApiException e) { Console.WriteLine($"OK duplicate rejected: {e.Message}"); }

            try { await api.CreateUserAsync("x@example.com", "Short", "short", []); Console.WriteLine("FAIL weak password accepted"); return 1; }
            catch (ApiException e) { Console.WriteLine($"OK weak password rejected: {e.Message}"); }

            Console.WriteLine("SELFTEST PASSED");
            return 0;
        }
        catch (Exception e)
        {
            Console.WriteLine("SELFTEST FAILED: " + e);
            return 1;
        }
    }
}
