package com.repoguard.scanner;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.repoguard.model.Severity;
import com.repoguard.model.Vulnerability;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class SQLInjectionScanner {

    public List<Vulnerability> scan(List<File> javaFiles) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (File file : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(file);
                // Track already-flagged lines to prevent duplicate detections
                Set<Integer> flaggedLines = new HashSet<>();

                cu.accept(new VoidVisitorAdapter<Void>() {

                    @Override
                    public void visit(BinaryExpr n, Void arg) {
                        // Do NOT call super.visit() — prevents re-visiting child nodes
                        int line = n.getBegin().isPresent() ? n.getBegin().get().line : 0;
                        if (n.getOperator() == BinaryExpr.Operator.PLUS && !flaggedLines.contains(line)) {
                            boolean hasSql = n.findAll(StringLiteralExpr.class).stream()
                                    .map(StringLiteralExpr::getValue)
                                    .map(String::toUpperCase)
                                    .anyMatch(val -> val.contains("SELECT ") || val.contains("INSERT ") ||
                                                     val.contains("UPDATE ") || val.contains("DELETE "));
                            if (hasSql) {
                                flaggedLines.add(line);
                                vulnerabilities.add(new Vulnerability(
                                        "SQL_INJECTION", Severity.CRITICAL, file.getName(), line,
                                        "AST Detection: SQL Injection via string concatenation in expression.",
                                        "Use PreparedStatement or parameterized queries."
                                ));
                            }
                        }
                        // Manually visit children to maintain traversal without duplication
                        n.getLeft().accept(this, arg);
                        n.getRight().accept(this, arg);
                    }

                    @Override
                    public void visit(MethodCallExpr n, Void arg) {
                        super.visit(n, arg);
                        int line = n.getBegin().isPresent() ? n.getBegin().get().line : 0;
                        String methodName = n.getNameAsString();
                        if ((methodName.equals("execute") || methodName.equals("executeQuery") || methodName.equals("executeUpdate"))
                                && n.getArguments().isNonEmpty()
                                && !(n.getArgument(0) instanceof StringLiteralExpr)
                                && !flaggedLines.contains(line)) {
                            flaggedLines.add(line);
                            vulnerabilities.add(new Vulnerability(
                                    "SQL_INJECTION", Severity.HIGH, file.getName(), line,
                                    "AST Detection: Unsafe SQL execution with dynamic argument.",
                                    "Replace with PreparedStatement to prevent injection."
                            ));
                        }
                    }
                }, null);

            } catch (Exception e) {
                System.out.println("Error parsing file with JavaParser: " + file.getName());
            }
        }

        return vulnerabilities;
    }
}
