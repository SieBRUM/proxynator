using System.Text.RegularExpressions;
using Proxynator.Core.Configuration;

namespace Proxynator.Core.Tests.Configuration;

/// <summary>
/// The README and the guides in docs/ must not rot: every complete configuration they show is valid, and every
/// relative link (and #anchor) points at something that exists.
/// </summary>
public partial class DocumentationTests
{
    private static readonly string Root = FindRepositoryRoot();

    public static TheoryData<string> Pages()
    {
        var data = new TheoryData<string>();
        foreach (var page in MarkdownPages())
        {
            data.Add(Path.GetRelativePath(Root, page).Replace('\\', '/'));
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public void Every_complete_configuration_example_is_valid(string page)
    {
        var markdown = File.ReadAllText(Path.Combine(Root, page));

        foreach (Match block in JsonBlock().Matches(markdown))
        {
            var json = block.Groups["json"].Value;
            if (!json.TrimStart().StartsWith('{') || !json.Contains("\"version\"", StringComparison.Ordinal))
            {
                continue; // a fragment ("settings": {...}), not a configuration
            }

            var result = ConfigLoader.Parse(json);
            Assert.True(result.Success, $"{page}, example at offset {block.Index}: {string.Join("; ", result.Errors)}");
        }
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public void Every_relative_link_points_at_something_that_exists(string page)
    {
        var path = Path.Combine(Root, page);
        var markdown = File.ReadAllText(path);

        foreach (Match link in Link().Matches(markdown))
        {
            var target = link.Groups["target"].Value;
            if (target.StartsWith("http", StringComparison.Ordinal) || target.StartsWith("mailto:", StringComparison.Ordinal))
            {
                continue;
            }

            var hash = target.IndexOf('#', StringComparison.Ordinal);
            var file = hash >= 0 ? target[..hash] : target;
            var anchor = hash >= 0 ? target[(hash + 1)..] : null;
            var resolved = file.Length == 0 ? path : Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, file));

            Assert.True(File.Exists(resolved) || Directory.Exists(resolved), $"{page}: broken link '{target}'");
            if (anchor is not null && resolved.EndsWith(".md", StringComparison.Ordinal))
            {
                Assert.Contains(anchor, Anchors(File.ReadAllText(resolved)));
            }
        }
    }

    [Fact]
    public void The_readme_and_guides_are_found() =>
        Assert.True(MarkdownPages().Count() > 10, $"Expected the README and the docs under {Root}.");

    private static IEnumerable<string> MarkdownPages() =>
        Directory.EnumerateFiles(Path.Combine(Root, "docs"), "*.md", SearchOption.AllDirectories)
            .Where(page => !page.Contains($"{Path.DirectorySeparatorChar}adr{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Prepend(Path.Combine(Root, "README.md"));

    /// <summary>GitHub's heading anchors: lower case, punctuation removed, spaces as dashes.</summary>
    private static HashSet<string> Anchors(string markdown) =>
    [
        .. Heading().Matches(markdown).Select(h => Slug().Replace(h.Groups["text"].Value.ToLowerInvariant(), string.Empty).Replace(' ', '-')),
    ];

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Proxynator.sln")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException($"Proxynator.sln not found above {AppContext.BaseDirectory}.");
    }

    [GeneratedRegex(@"```json\r?\n(?<json>.*?)```", RegexOptions.Singleline)]
    private static partial Regex JsonBlock();

    [GeneratedRegex(@"\]\((?<target>[^)\s]+)\)")]
    private static partial Regex Link();

    [GeneratedRegex(@"^#{1,6}\s+(?<text>.+?)\s*$", RegexOptions.Multiline)]
    private static partial Regex Heading();

    [GeneratedRegex(@"[^a-z0-9 _-]")]
    private static partial Regex Slug();
}
