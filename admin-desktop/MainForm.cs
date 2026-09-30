using System.Diagnostics;
using System.Security.Cryptography;

namespace IdentityAdmin;

/// <summary>One window: sign in, create an account, see and enable/disable accounts. Plain on purpose.</summary>
internal sealed class MainForm : Form
{
    // No look-alike characters (0/O, 1/l/I), so a password read out or copied by hand is not misread.
    private const string PasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    private const int PageSize = 100;

    private readonly TextBox _server = new() { Width = 260 };
    private readonly Button _signIn = new() { Text = "Sign in", AutoSize = true };
    private readonly Label _status = new() { AutoSize = true, Text = "Not signed in", Padding = new Padding(0, 6, 0, 0) };

    private readonly TextBox _email = new() { Dock = DockStyle.Fill };
    private readonly TextBox _name = new() { Dock = DockStyle.Fill };
    private readonly TextBox _password = new() { Dock = DockStyle.Fill };
    private readonly Button _generate = new() { Text = "Generate", AutoSize = true };
    private readonly Button _copy = new() { Text = "Copy", AutoSize = true };
    private readonly CheckedListBox _roles = new() { Dock = DockStyle.Fill, CheckOnClick = true, Height = 90 };
    private readonly Button _create = new() { Text = "Create account", AutoSize = true };
    private readonly Label _result = new() { Dock = DockStyle.Fill, AutoSize = false, Height = 60 };

    private readonly TextBox _search = new() { Width = 220, PlaceholderText = "Search email or name" };
    private readonly Button _refresh = new() { Text = "Search / refresh", AutoSize = true };
    private readonly Button _toggle = new() { Text = "Disable / enable selected", AutoSize = true };
    private readonly DataGridView _grid = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = false, RowHeadersVisible = false,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill, BackgroundColor = SystemColors.Window,
    };
    private readonly Label _count = new() { AutoSize = true, Padding = new Padding(0, 6, 0, 0) };

    private AuthClient? _auth;
    private ApiClient? _api;
    private List<UserRow> _users = [];

    public MainForm(string server)
    {
        // Sizes below are in pixels at 96 DPI; scale them on high-DPI screens so nothing is clipped.
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "Identity Admin";
        MinimumSize = new Size(980, 560);
        Size = new Size(1120, 680);
        _server.Text = server;

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(10, 10, 10, 6) };
        top.Controls.AddRange([new Label { Text = "Identity server", AutoSize = true, Padding = new Padding(0, 6, 0, 0) }, _server, _signIn, _status]);

        // left: create an account
        var form = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new Padding(10), AutoSize = true };
        form.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        form.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        void Row(string label, Control control)
        {
            form.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 8, 0) });
            form.Controls.Add(control);
        }
        Row("Email", _email);
        Row("Display name", _name);
        var pw = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = false };
        _password.Dock = DockStyle.None;
        _password.Width = 135;
        pw.Controls.AddRange([_password, _generate, _copy]);
        Row("Initial password", pw);
        Row("Roles", _roles);
        form.Controls.Add(new Label());
        form.Controls.Add(_create);
        form.Controls.Add(new Label());
        form.SetColumnSpan(_result, 1);
        form.Controls.Add(_result);

        var createBox = new GroupBox { Text = "Create an account", Dock = DockStyle.Left, Width = 480, Padding = new Padding(4) };
        createBox.Controls.Add(form);

        // right: the accounts
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(0, 0, 0, 6) };
        bar.Controls.AddRange([_search, _refresh, _toggle, _count]);
        var listBox = new GroupBox { Text = "Accounts", Dock = DockStyle.Fill, Padding = new Padding(8) };
        listBox.Controls.Add(_grid);
        listBox.Controls.Add(bar);

        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10, 0, 10, 10) };
        body.Controls.Add(listBox);
        body.Controls.Add(new Panel { Dock = DockStyle.Left, Width = 10 });
        body.Controls.Add(createBox);

        Controls.Add(body);
        Controls.Add(top);

        _grid.Columns.Add("email", "Email");
        _grid.Columns.Add("name", "Name");
        _grid.Columns.Add("roles", "Roles");
        _grid.Columns.Add("active", "Status");
        _grid.Columns.Add("mfa", "MFA");
        _grid.Columns.Add("created", "Created");

        _password.UseSystemPasswordChar = false; // shown on purpose: the admin has to hand it to the person
        SetSignedIn(false);

        _signIn.Click += async (_, _) => await SignInAsync();
        _generate.Click += (_, _) => _password.Text = NewPassword();
        _copy.Click += (_, _) => { if (_password.Text.Length > 0) Clipboard.SetText(_password.Text); };
        _create.Click += async (_, _) => await CreateAsync();
        _refresh.Click += async (_, _) => await LoadUsersAsync();
        _search.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await LoadUsersAsync(); } };
        _toggle.Click += async (_, _) => await ToggleAsync();
    }

    private void SetSignedIn(bool signedIn)
    {
        foreach (Control c in new Control[] { _email, _name, _password, _generate, _copy, _roles, _create, _search, _refresh, _toggle, _grid })
            c.Enabled = signedIn;
    }

    private async Task RunAsync(Func<Task> action)
    {
        try { await action(); }
        catch (Exception e) when (e is ApiException or HttpRequestException or TimeoutException or InvalidOperationException or TaskCanceledException)
        {
            _result.ForeColor = Color.Firebrick;
            _result.Text = e.Message;
        }
    }

    private async Task SignInAsync()
    {
        _signIn.Enabled = false;
        await RunAsync(async () =>
        {
            _auth = new AuthClient(_server.Text.Trim(), url => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }));
            _api = new ApiClient(_auth);
            _status.Text = "Waiting for you to sign in in the browser...";
            await _auth.SignInAsync();
            _status.Text = $"Signed in as {_auth.Email}";
            _result.Text = "";

            var roles = await _api.RolesAsync();
            _roles.Items.Clear();
            foreach (var role in roles) _roles.Items.Add(role.Name, isChecked: role.Name == "operator");
            SetSignedIn(true);
            await LoadUsersAsync();
        });
        if (_auth is null || _status.Text.StartsWith("Waiting")) _status.Text = "Not signed in";
        _signIn.Enabled = true;
    }

    private async Task LoadUsersAsync()
    {
        if (_api is null) return;
        await RunAsync(async () =>
        {
            var page = await _api.UsersAsync(_search.Text, 1, PageSize);
            _users = page.Items;
            _grid.Rows.Clear();
            foreach (var u in _users)
                _grid.Rows.Add(u.Email, u.DisplayName, string.Join(", ", u.Roles), u.IsActive ? "Active" : "Disabled",
                    u.MfaEnabled ? "On" : "Off", u.CreatedAt.LocalDateTime.ToString("yyyy-MM-dd"));
            _count.Text = page.Total > _users.Count ? $"showing {_users.Count} of {page.Total}" : $"{page.Total} accounts";
        });
    }

    private async Task CreateAsync()
    {
        if (_api is null) return;
        var email = _email.Text.Trim();
        if (!email.Contains('@')) { Fail("Enter a valid email address."); return; }
        if (_name.Text.Trim().Length == 0) { Fail("Enter a display name."); return; }
        if (_password.Text.Length < 12) { Fail("The password must be at least 12 characters. Use Generate for a strong one."); return; }

        _create.Enabled = false;
        await RunAsync(async () =>
        {
            var password = _password.Text;
            var roles = _roles.CheckedItems.Cast<string>().ToList();
            var created = await _api.CreateUserAsync(email, _name.Text.Trim(), password, roles);
            _result.ForeColor = Color.DarkGreen;
            _result.Text = $"Created {created.Email} ({(roles.Count == 0 ? "no roles" : string.Join(", ", roles))}).\r\n" +
                           "Give them the password above; it is not shown again after you clear it.";
            _email.Clear();
            _name.Clear();
            await LoadUsersAsync();
        });
        _create.Enabled = true;
    }

    private void Fail(string message)
    {
        _result.ForeColor = Color.Firebrick;
        _result.Text = message;
    }

    private async Task ToggleAsync()
    {
        if (_api is null || _grid.CurrentRow is null || _grid.CurrentRow.Index >= _users.Count) return;
        var user = _users[_grid.CurrentRow.Index];
        var verb = user.IsActive ? "Disable" : "Enable";
        var extra = user.IsActive ? "\r\nThey will be signed out everywhere." : "";
        if (MessageBox.Show(this, $"{verb} {user.Email}?{extra}", "Identity Admin", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

        await RunAsync(async () =>
        {
            await _api.SetActiveAsync(user.Id, !user.IsActive);
            _result.ForeColor = Color.DarkGreen;
            _result.Text = $"{(user.IsActive ? "Disabled" : "Enabled")} {user.Email}.";
            await LoadUsersAsync();
        });
    }

    public static string NewPassword(int length = 16)
    {
        var chars = new char[length];
        for (var i = 0; i < length; i++) chars[i] = PasswordAlphabet[RandomNumberGenerator.GetInt32(PasswordAlphabet.Length)];
        return new string(chars);
    }
}
