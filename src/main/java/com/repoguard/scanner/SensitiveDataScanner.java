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
import java.util.List;

@Component
public class SensitiveDataScanner {

    public List<Vulnerability> scan(List<File> javaFiles) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (File file : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(file);
                
                cu.accept(new VoidVisitorAdapter<List<Vulnerability>>() {
                    
                    @Override
                    public void visit(VariableDeclarator n, List<Vulnerability> arg) {
                        super.visit(n, arg);
                        String varName = n.getNameAsString().toLowerCase();
                        
                        // Check if it's assigned a hardcoded string
                        if (n.getInitializer().isPresent() && n.getInitializer().get() instanceof StringLiteralExpr) {
                            checkAndFlag(varName, n.getBegin().isPresent() ? n.getBegin().get().line : 0, arg, file.getName());
                        }
                    }

                    @Override
                    public void visit(AssignExpr n, List<Vulnerability> arg) {
                        super.visit(n, arg);
                        String targetName = n.getTarget().toString().toLowerCase();
                        
                        // Check if it's assigned a hardcoded string
                        if (n.getValue() instanceof StringLiteralExpr) {
                            checkAndFlag(targetName, n.getBegin().isPresent() ? n.getBegin().get().line : 0, arg, file.getName());
                        }
                    }
                    
                    private void checkAndFlag(String name, int line, List<Vulnerability> arg, String fileName) {
                        if (name.contains("password")) {
                            arg.add(new Vulnerability("HARDCODED_SECRET", Severity.HIGH, fileName, line,
                                    "AST Detection: Hardcoded password literal assigned to variable.",
                                    "Use environment variables or a secrets manager."));
                        } else if (name.contains("apikey") || name.contains("api_key")) {
                            arg.add(new Vulnerability("HARDCODED_SECRET", Severity.HIGH, fileName, line,
                                    "AST Detection: Hardcoded API key literal assigned to variable.",
                                    "Use environment variables or a secrets manager."));
                        } else if (name.contains("token")) {
                            arg.add(new Vulnerability("HARDCODED_SECRET", Severity.HIGH, fileName, line,
                                    "AST Detection: Hardcoded token literal assigned to variable.",
                                    "Use environment variables or a secrets manager."));
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
