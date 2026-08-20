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
import java.util.List;

@Component
public class SQLInjectionScanner {

    public List<Vulnerability> scan(List<File> javaFiles) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (File file : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(file);
                
                // Visitor to find AST nodes representing vulnerabilities
                cu.accept(new VoidVisitorAdapter<List<Vulnerability>>() {
                    
                    @Override
                    public void visit(BinaryExpr n, List<Vulnerability> arg) {
                        super.visit(n, arg);
                        // Check for string concatenation (Operator.PLUS)
                        if (n.getOperator() == BinaryExpr.Operator.PLUS) {
                            // Does this concatenation involve a SQL keyword in a string literal?
                            boolean hasSql = n.findAll(StringLiteralExpr.class).stream()
                                    .map(StringLiteralExpr::getValue)
                                    .map(String::toUpperCase)
                                    .anyMatch(val -> val.contains("SELECT ") || val.contains("INSERT ") || 
                                                     val.contains("UPDATE ") || val.contains("DELETE "));
                            
                            if (hasSql) {
                                arg.add(new Vulnerability(
                                        "SQL_INJECTION",
                                        Severity.CRITICAL,
                                        file.getName(),
                                        n.getBegin().isPresent() ? n.getBegin().get().line : 0,
                                        "AST Detection: SQL Injection via string concatenation in expression.",
                                        "Use PreparedStatement or parameterized queries."
                                ));
                            }
                        }
                    }

                    @Override
                    public void visit(MethodCallExpr n, List<Vulnerability> arg) {
                        super.visit(n, arg);
                        String methodName = n.getNameAsString();
                        // Look for raw execute calls common in JDBC Statement
                        if (methodName.equals("execute") || methodName.equals("executeQuery") || methodName.equals("executeUpdate")) {
                            // If the argument is a BinaryExpr (concatenation) or NameExpr (variable), it's highly suspicious
                            if (n.getArguments().isNonEmpty() && !(n.getArgument(0) instanceof StringLiteralExpr)) {
                                arg.add(new Vulnerability(
                                        "SQL_INJECTION",
                                        Severity.HIGH,
                                        file.getName(),
                                        n.getBegin().isPresent() ? n.getBegin().get().line : 0,
                                        "AST Detection: Unsafe SQL execution with dynamic argument.",
                                        "Replace with PreparedStatement to prevent injection."
                                ));
                            }
                        }
                    }
                }, vulnerabilities);

            } catch (Exception e) {
                System.out.println("Error parsing file with JavaParser: " + file.getName());
            }
        }

        return vulnerabilities;
    }
}
