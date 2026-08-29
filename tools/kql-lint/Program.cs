// kql-lint — valida sintaxis KQL con el parser REAL de Microsoft.
//
// POR QUE EXISTE ESTE PROGRAMA
// La alternativa barata era validar el KQL con expresiones regulares. No lo hicimos, y la
// razon importa mas que el codigo: una heuristica no valida sintaxis, la *aparenta*. Aceptaria
// `SigninLogs | wher ResultType == 0` (un `where` mal escrito) y rechazaria consultas validas
// que usen algo que el autor de la regex no previo. Un repo que dice "valido KQL" mientras
// hace grep esta mintiendo en su propio README.
//
// Aca se usa `Microsoft.Azure.Kusto.Language`, la MISMA libreria con la que Azure Data Explorer
// analiza las consultas. Si el parser dice que algo esta mal, esta mal de verdad.
//
// LIMITE HONESTO, y hay que decirlo: esto valida SINTAXIS, no semantica. Sin conocer el esquema
// de las tablas de un tenant, el parser no puede saber si `SigninLogs` tiene una columna
// `ResultTye`. Detecta que la consulta esta bien FORMADA, no que vaya a devolver algo.
// Esa distincion esta documentada en el README y en el ADR: prometer mas seria el mismo
// problema que las regex, con mejor disfraz.
//
// USO:  kql-lint <archivo.kql> [<archivo.kql> ...]
//       kql-lint --stdin  < consulta.kql
// SALIDA: JSON por stdout. Codigo 0 si todo parsea, 1 si hay errores, 2 si fallo el programa.

using System.Text.Json;
using Kusto.Language;

namespace KqlLint;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            var queries = new List<(string Source, string Text)>();

            if (args.Length == 1 && args[0] == "--stdin")
            {
                queries.Add(("<stdin>", Console.In.ReadToEnd()));
            }
            else if (args.Length == 0)
            {
                Console.Error.WriteLine("uso: kql-lint <archivo.kql> [...] | kql-lint --stdin");
                return 2;
            }
            else
            {
                foreach (var path in args)
                {
                    if (!File.Exists(path))
                    {
                        Console.Error.WriteLine($"no existe: {path}");
                        return 2;
                    }
                    queries.Add((path, File.ReadAllText(path)));
                }
            }

            var results = new List<object>();
            var anyError = false;

            foreach (var (source, text) in queries)
            {
                // KustoCode.Parse hace el analisis lexico y sintactico completo.
                // No se usa ParseAndAnalyze porque eso exige el esquema de las tablas, que
                // depende del tenant y no lo tenemos en CI. Ver el limite honesto de arriba.
                var code = KustoCode.Parse(text);
                var diagnostics = code.GetSyntaxDiagnostics();

                var items = diagnostics.Select(d => new
                {
                    severity = d.Severity,
                    code = d.Code,
                    message = d.Message,
                    // El parser da offsets absolutos; se traducen a linea/columna para que el
                    // error sea accionable sin contar caracteres a mano.
                    line = LineOf(text, d.Start),
                    column = ColumnOf(text, d.Start),
                    start = d.Start,
                    length = d.Length
                }).ToList();

                if (items.Count > 0) anyError = true;

                results.Add(new
                {
                    source,
                    ok = items.Count == 0,
                    diagnostics = items
                });
            }

            var opts = new JsonSerializerOptions { WriteIndented = true };
            Console.Out.WriteLine(JsonSerializer.Serialize(new
            {
                tool = "kql-lint",
                parser = "Microsoft.Azure.Kusto.Language",
                checks = "syntax-only",
                results
            }, opts));

            return anyError ? 1 : 0;
        }
        catch (Exception ex)
        {
            // Fail-closed y ruidoso: si el linter no pudo correr, NO se reporta "todo bien".
            Console.Error.WriteLine($"kql-lint fallo: {ex.GetType().Name}: {ex.Message}");
            return 2;
        }
    }

    private static int LineOf(string text, int offset)
    {
        var line = 1;
        for (var i = 0; i < offset && i < text.Length; i++)
            if (text[i] == '\n') line++;
        return line;
    }

    private static int ColumnOf(string text, int offset)
    {
        var col = 1;
        for (var i = 0; i < offset && i < text.Length; i++)
            col = text[i] == '\n' ? 1 : col + 1;
        return col;
    }
}
