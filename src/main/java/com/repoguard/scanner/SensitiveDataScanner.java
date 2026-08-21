package com.repoguard.scanner;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
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
public class SensitiveDataScanner {

    public List<Vulnerability> scan(List<File> javaFiles) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (File file : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(file);
                Set<Integer> flaggedLines = new HashSet<>();

                cu.accept(new VoidVisitorAdapter<Void>() {

                    @Override
                    public void visit(VariableDeclarator n, Void arg) {
                        super.visit(n, arg);
                        int line = n.getBegin().isPresent() ? n.getBegin().get().line : 0;
                        String varName = n.getNameAsString().toLowerCase();

                        if (n.getInitializer().isPresent()
                                && n.getInitializer().get() instanceof StringLiteralExpr
                                && !flaggedLines.contains(line)) {
                            if (checkAndFlag(varName, line, vulnerabilities, file.getName())) {
                                flaggedLines.add(line);
                            }
                        }
                    }

                    @Override
                    public void visit(AssignExpr n, Void arg) {
                        super.visit(n, arg);
                        int line = n.getBegin().isPresent() ? n.getBegin().get().line : 0;
                        String targetName = n.getTarget().toString().toLowerCase();

                        if (n.getValue() instanceof StringLiteralExpr && !flaggedLines.contains(line)) {
                            if (checkAndFlag(targetName, line, vulnerabilities, file.getName())) {
                                flaggedLines.add(line);
                            }
                        }
                    }

                    private boolean checkAndFlag(String name, int line, List<Vulnerability> list, String fileName) {
                        if (name.contains("password")) {
                            list.add(new Vulnerability("HARDCODED_SECRET", Severity.HIGH, fileName, line,
                                    "AST Detection: Hardcoded password literal assigned to variable.",
                                    "Use environment variables or a secrets manager."));
                            return true;
                        } else if (name.contains("apikey") || name.contains("api_key")) {
                            list.add(new Vulnerability("HARDCODED_SECRET", Severity.HIGH, fileName, line,
                                    "AST Detection: Hardcoded API key literal assigned to variable.",
                                    "Use environment variables or a secrets manager."));
                            return true;
                        } else if (name.contains("token")) {
                            list.add(new Vulnerability("HARDCODED_SECRET", Severity.HIGH, fileName, line,
                                    "AST Detection: Hardcoded token literal assigned to variable.",
                                    "Use environment variables or a secrets manager."));
                            return true;
                        }
                        return false;
                    }
                }, null);

            } catch (Exception e) {
                System.out.println("Error parsing file with JavaParser: " + file.getName());
            }
        }

        return vulnerabilities;
    }
}
